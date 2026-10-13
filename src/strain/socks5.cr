require "socket"
require "./target"

module Strain
  module Socks5
    record Proxy, host : String, port : Int32, username : String?, password : String?

    class Pool
      getter proxies : Array(Proxy)
      getter timeout : Time::Span

      @next = Atomic(Int64).new(0_i64)

      def initialize(@proxies : Array(Proxy), @timeout : Time::Span)
        if @proxies.empty?
          raise ArgumentError.new("SOCKS5 proxy list is empty")
        end
      end

      def self.from_file(path : String, timeout : Time::Span) : Pool
        proxies = [] of Proxy
        File.each_line(path) do |line|
          raw = line.strip
          next if raw.empty? || raw.starts_with?("#")
          if comment = raw.index('#')
            raw = raw[0, comment].strip
          end
          next if raw.empty?
          proxies << parse_proxy(raw)
        end
        Pool.new(proxies, timeout)
      end

      def self.parse_proxy(raw : String) : Proxy
        spec = raw
        spec = spec["socks5://".size..] if spec.starts_with?("socks5://")

        username = nil
        password = nil
        if at = spec.rindex('@')
          auth = spec[0, at]
          spec = spec[(at + 1)..]
          user, sep, pass = auth.partition(":")
          username = user
          password = sep.empty? ? "" : pass
        end

        host, sep, port_s = spec.rpartition(":")
        if sep.empty? || host.empty?
          raise ArgumentError.new("invalid SOCKS5 proxy '#{raw}', expected host:port or user:pass@host:port")
        end
        port = port_s.to_i?
        unless port && port > 0 && port <= 65_535
          raise ArgumentError.new("invalid SOCKS5 proxy port in '#{raw}'")
        end

        Proxy.new(host, port, username, password)
      end

      def open(target : Target) : UDPAssociate
        index = @next.add(1_i64)
        proxy = @proxies[(index % @proxies.size).to_i]
        UDPAssociate.new(proxy, target, @timeout)
      end

      def send_once(target : Target, payload : Bytes) : Bool
        session = open(target)
        session.send(payload)
        true
      ensure
        session.try &.close rescue nil
      end
    end

    class UDPAssociate
      @tcp : TCPSocket
      @udp : UDPSocket
      @relay : Socket::IPAddress

      def initialize(@proxy : Proxy, @target : Target, @timeout : Time::Span)
        @tcp = TCPSocket.new(@proxy.host, @proxy.port, nil, @timeout)
        @tcp.read_timeout = @timeout
        @tcp.write_timeout = @timeout
        negotiate!
        @relay = udp_associate!
        @udp = UDPSocket.new
        @udp.bind "0.0.0.0", 0
        @udp.read_timeout = @timeout
      end

      def send(payload : Bytes) : Nil
        packet = build_udp_packet(payload)
        @udp.send(packet, to: @relay)
      end

      def receive(buf : Bytes) : Int32?
        raw = Bytes.new(buf.size + 512)
        n, _ = @udp.receive(raw)
        return nil if n < 4
        return nil unless raw[0] == 0_u8 && raw[1] == 0_u8 && raw[2] == 0_u8

        offset = 3
        case raw[offset]
        when 0x01_u8
          offset += 1 + 4 + 2
        when 0x03_u8
          offset += 1
          return nil if offset >= n
          len = raw[offset].to_i
          offset += 1 + len + 2
        when 0x04_u8
          offset += 1 + 16 + 2
        else
          return nil
        end
        return nil if offset > n

        payload_len = n - offset
        return 0 if payload_len == 0
        copy_len = {payload_len, buf.size}.min
        buf[0, copy_len].copy_from(raw[offset, copy_len])
        copy_len
      rescue IO::TimeoutError
        nil
      end

      def close
        @udp.close rescue nil
        @tcp.close rescue nil
      end

      private def negotiate!
        if @proxy.username
          @tcp.write Bytes[0x05_u8, 0x02_u8, 0x00_u8, 0x02_u8]
        else
          @tcp.write Bytes[0x05_u8, 0x01_u8, 0x00_u8]
        end

        response = read_exact(2)
        unless response[0] == 0x05_u8
          raise IO::Error.new("SOCKS5 #{@proxy.host}:#{@proxy.port} returned invalid greeting")
        end

        case response[1]
        when 0x00_u8
          return
        when 0x02_u8
          authenticate!
        when 0xff_u8
          raise IO::Error.new("SOCKS5 #{@proxy.host}:#{@proxy.port} has no acceptable auth method")
        else
          raise IO::Error.new("SOCKS5 #{@proxy.host}:#{@proxy.port} selected unsupported auth method #{response[1]}")
        end
      end

      private def authenticate!
        username = @proxy.username || ""
        password = @proxy.password || ""
        if username.bytesize > 255 || password.bytesize > 255
          raise IO::Error.new("SOCKS5 username/password too long for #{@proxy.host}:#{@proxy.port}")
        end

        packet = Bytes.new(3 + username.bytesize + password.bytesize)
        packet[0] = 0x01_u8
        packet[1] = username.bytesize.to_u8
        packet[2, username.bytesize].copy_from(username.to_slice)
        pass_offset = 2 + username.bytesize
        packet[pass_offset] = password.bytesize.to_u8
        packet[(pass_offset + 1), password.bytesize].copy_from(password.to_slice)
        @tcp.write(packet)

        response = read_exact(2)
        unless response[0] == 0x01_u8 && response[1] == 0x00_u8
          raise IO::Error.new("SOCKS5 #{@proxy.host}:#{@proxy.port} authentication failed")
        end
      end

      private def udp_associate! : Socket::IPAddress
        @tcp.write Bytes[
          0x05_u8, 0x03_u8, 0x00_u8, 0x01_u8,
          0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8,
          0x00_u8, 0x00_u8,
        ]

        version, reply, atyp = read_reply_header
        unless version == 0x05_u8 && reply == 0x00_u8
          raise IO::Error.new("SOCKS5 #{@proxy.host}:#{@proxy.port} UDP ASSOCIATE failed with reply #{reply}")
        end

        host = read_address(atyp)
        port = read_u16_be
        host = @proxy.host if host == "0.0.0.0" || host == "::"
        Socket::IPAddress.new(host, port)
      end

      private def build_udp_packet(payload : Bytes) : Bytes
        target_host = @target.host == "localhost" ? "127.0.0.1" : @target.host
        ipv4 = parse_ipv4?(target_host)
        header_len = if ipv4
                       3 + 1 + 4 + 2
                     else
                       host_size = target_host.bytesize
                       if host_size > 255
                         raise IO::Error.new("SOCKS5 UDP target host is too long: #{target_host}")
                       end
                       3 + 1 + 1 + host_size + 2
                     end

        packet = Bytes.new(header_len + payload.size)
        packet[0] = 0_u8
        packet[1] = 0_u8
        packet[2] = 0_u8
        offset = 3
        if ip = ipv4
          packet[offset] = 0x01_u8
          offset += 1
          packet[offset] = ((ip >> 24) & 0xff_u32).to_u8
          packet[offset + 1] = ((ip >> 16) & 0xff_u32).to_u8
          packet[offset + 2] = ((ip >> 8) & 0xff_u32).to_u8
          packet[offset + 3] = (ip & 0xff_u32).to_u8
          offset += 4
        else
          packet[offset] = 0x03_u8
          offset += 1
          packet[offset] = target_host.bytesize.to_u8
          offset += 1
          packet[offset, target_host.bytesize].copy_from(target_host.to_slice)
          offset += target_host.bytesize
        end
        write_u16_be(packet, offset, @target.port)
        offset += 2
        packet[offset, payload.size].copy_from(payload)
        packet
      end

      private def read_reply_header : {UInt8, UInt8, UInt8}
        head = read_exact(4)
        unless head[2] == 0x00_u8
          raise IO::Error.new("SOCKS5 #{@proxy.host}:#{@proxy.port} returned invalid reserved byte")
        end
        {head[0], head[1], head[3]}
      end

      private def read_address(atyp : UInt8) : String
        case atyp
        when 0x01_u8
          data = read_exact(4)
          "#{data[0]}.#{data[1]}.#{data[2]}.#{data[3]}"
        when 0x03_u8
          len = read_exact(1)[0].to_i
          String.new(read_exact(len))
        when 0x04_u8
          data = read_exact(16)
          groups = [] of String
          8.times do |i|
            v = (data[i * 2].to_u16 << 8) | data[i * 2 + 1].to_u16
            groups << v.to_s(16)
          end
          groups.join(":")
        else
          raise IO::Error.new("SOCKS5 #{@proxy.host}:#{@proxy.port} returned unsupported ATYP #{atyp}")
        end
      end

      private def read_u16_be : Int32
        data = read_exact(2)
        ((data[0].to_i << 8) | data[1].to_i)
      end

      private def read_exact(size : Int32) : Bytes
        buf = Bytes.new(size)
        @tcp.read_fully(buf)
        buf
      end

      private def write_u16_be(buf : Bytes, offset : Int32, value : Int32)
        buf[offset] = ((value >> 8) & 0xff).to_u8
        buf[offset + 1] = (value & 0xff).to_u8
      end

      private def parse_ipv4?(host : String) : UInt32?
        parts = host.split(".")
        return nil unless parts.size == 4

        value = 0_u32
        parts.each do |part|
          octet = part.to_i?
          return nil unless octet && 0 <= octet <= 255
          value = (value << 8) | octet.to_u32
        end
        value
      end
    end
  end
end
