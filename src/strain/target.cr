module Strain
  # Resolved target endpoint.
  struct Target
    getter host : String
    getter port : Int32

    def initialize(@host : String, @port : Int32)
    end

    # Parse "host:port" -- host defaults to 127.0.0.1 if missing.
    def self.parse(spec : String) : Target
      host, _, port_s = spec.rpartition(":")
      host = "127.0.0.1" if host.empty?
      Target.new(host, port_s.to_i)
    end

    def to_s(io : IO)
      io << @host << ':' << @port
    end
  end
end
