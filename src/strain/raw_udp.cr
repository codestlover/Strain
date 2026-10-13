require "socket"

module Strain
  module RawUDP
    SOURCE_PORT_BASE = 1024
    IPV4_HEADER_BYTES = 20
    UDP_HEADER_BYTES = 8
    IP_HDRINCL = 3

    def self.parse_ipv4_u32(host : String) : UInt32
      normalized = host == "localhost" ? "127.0.0.1" : host
      parts = normalized.split(".")
      raise ArgumentError.new("expected IPv4 address, got #{host}") unless parts.size == 4

      value = 0_u32
      parts.each do |part|
        octet = part.to_i?
        raise ArgumentError.new("invalid IPv4 address #{host}") unless octet && 0 <= octet <= 255
        value = (value << 8) | octet.to_u32
      end
      value
    end

    def self.validate_spoof_range!(spoof_base : String, spoof_ips : Int32, spoof_ports : Int32) : UInt32
      source_base = parse_ipv4_u32(spoof_base)
      if spoof_ips < 1
        STDERR.puts "--spoof-ips must be >= 1."
        exit 2
      end
      if spoof_ports < 1 || spoof_ports > (65535 - SOURCE_PORT_BASE + 1)
        STDERR.puts "--spoof-ports must be between 1 and #{65535 - SOURCE_PORT_BASE + 1}."
        exit 2
      end
      source_last_u64 = source_base.to_u64 + spoof_ips.to_u64 - 1_u64
      if source_last_u64 > UInt32::MAX
        STDERR.puts "--spoof-ips runs past IPv4 address space from #{spoof_base}."
        exit 2
      end
      source_base
    end

    @[AlwaysInline]
    def self.max_endpoints(spoof_ips : Int32, spoof_ports : Int32) : Int64
      spoof_ips.to_i64 * spoof_ports.to_i64
    end

    @[AlwaysInline]
    def self.endpoint_at(source_base : UInt32, spoof_ports : Int32, index : Int64) : {UInt32, Int32}
      ip_offset = index // spoof_ports
      port_offset = index % spoof_ports
      {source_base + ip_offset.to_u32, SOURCE_PORT_BASE + port_offset.to_i32}
    end

    def self.write_u16_be(buf : Bytes, offset : Int, value : UInt32)
      v = value & 0xffff_u32
      buf[offset] = ((v >> 8) & 0xff_u32).to_u8
      buf[offset + 1] = (v & 0xff_u32).to_u8
    end

    def self.write_u32_be(buf : Bytes, offset : Int, value : UInt32)
      buf[offset] = ((value >> 24) & 0xff_u32).to_u8
      buf[offset + 1] = ((value >> 16) & 0xff_u32).to_u8
      buf[offset + 2] = ((value >> 8) & 0xff_u32).to_u8
      buf[offset + 3] = (value & 0xff_u32).to_u8
    end

    def self.write_ipv4_socket_address!(buf : Bytes, offset : Int, ip : UInt32, port : Int32)
      buf[offset] = 0x02_u8
      buf[offset + 1] = 0x00_u8
      write_u16_be(buf, offset + 2, port.to_u32)
      buf[offset + 4] = ((ip >> 24) & 0xff_u32).to_u8
      buf[offset + 5] = ((ip >> 16) & 0xff_u32).to_u8
      buf[offset + 6] = ((ip >> 8) & 0xff_u32).to_u8
      buf[offset + 7] = (ip & 0xff_u32).to_u8
      i = offset + 8
      while i < offset + 16
        buf[i] = 0_u8
        i += 1
      end
    end

    def self.ipv4_checksum(header : Bytes) : UInt16
      sum = 0_u32
      i = 0
      while i < IPV4_HEADER_BYTES
        sum += ((header[i].to_u32 << 8) | header[i + 1].to_u32)
        i += 2
      end
      while (sum >> 16) != 0
        sum = (sum & 0xffff_u32) + (sum >> 16)
      end
      (~sum & 0xffff_u32).to_u16
    end

    def self.packet_size(payload_size : Int32) : Int32
      IPV4_HEADER_BYTES + UDP_HEADER_BYTES + payload_size
    end

    def self.build_packet!(packet : Bytes, payload : Bytes, *,
                           src_ip : UInt32, dst_ip : UInt32,
                           src_port : Int32, dst_port : Int32,
                           ident : UInt32)
      payload_offset = IPV4_HEADER_BYTES + UDP_HEADER_BYTES
      total_len = payload_offset + payload.size
      udp_len = UDP_HEADER_BYTES + payload.size

      packet.fill(0_u8)
      packet[0] = 0x45_u8
      write_u16_be(packet, 2, total_len.to_u32)
      write_u16_be(packet, 4, ident)
      packet[8] = 64_u8
      packet[9] = LibC::IPPROTO_UDP.to_u8
      write_u32_be(packet, 12, src_ip)
      write_u32_be(packet, 16, dst_ip)
      checksum = ipv4_checksum(packet[0, IPV4_HEADER_BYTES])
      write_u16_be(packet, 10, checksum.to_u32)

      write_u16_be(packet, IPV4_HEADER_BYTES, src_port.to_u32)
      write_u16_be(packet, IPV4_HEADER_BYTES + 2, dst_port.to_u32)
      write_u16_be(packet, IPV4_HEADER_BYTES + 4, udp_len.to_u32)
      packet[payload_offset, payload.size].copy_from(payload)
    end

    def self.sockaddr(ip : UInt32, port : Int32) : Socket::IPAddress
      Socket::IPAddress.v4(
        ((ip >> 24) & 0xff_u32).to_i,
        ((ip >> 16) & 0xff_u32).to_i,
        ((ip >> 8) & 0xff_u32).to_i,
        (ip & 0xff_u32).to_i,
        port: port
      )
    end

    def self.open_socket : Int32
      fd = LibC.socket(LibC::AF_INET, LibC::SOCK_RAW, LibC::IPPROTO_RAW)
      if fd < 0
        raise IO::Error.new("raw socket failed: #{Errno.value.message}")
      end

      one = 1
      rc = LibC.setsockopt(
        fd,
        LibC::IPPROTO_IP,
        IP_HDRINCL,
        pointerof(one).as(Void*),
        sizeof(Int32).to_u32
      )
      if rc < 0
        errno = Errno.value
        LibC.close(fd)
        raise IO::Error.new("IP_HDRINCL failed: #{errno.message}")
      end

      fd
    end

    def self.send_packet(fd : Int32, address : Socket::IPAddress, packet : Bytes) : Bool
      sent = LibC.sendto(
        fd,
        packet.to_unsafe.as(Void*),
        packet.size,
        0,
        address.to_unsafe,
        sizeof(LibC::SockaddrIn).to_u32
      )
      sent == packet.size
    end

    def self.pace_total_rate(seq : Int64, pps : Int32, started_at : Time::Span)
      return if pps <= 0

      target_elapsed = seq.to_f / pps.to_f
      actual_elapsed = (Time.monotonic - started_at).total_seconds
      delay = target_elapsed - actual_elapsed
      sleep delay.seconds if delay > 0
    end

    def self.udp_drops_for_port(port : Int32) : Int64?
      total = 0_i64
      found = false
      {"/proc/net/udp", "/proc/net/udp6"}.each do |path|
        next unless File.exists?(path)

        File.each_line(path) do |line|
          fields = line.strip.split
          next if fields.size < 13 || fields[0] == "sl"
          local = fields[1]?
          local_port = local.try &.split(":")[1]?
          next unless local_port
          next unless local_port.to_i(16) == port

          if drops = fields[-1].to_i64?
            total += drops
            found = true
          end
        end
      end
      found ? total : nil
    rescue
      nil
    end

    def self.accepted_estimate(packets : Int64, udp_drops_delta : Int64?) : Int64?
      return nil unless udp_drops_delta

      estimate = packets - udp_drops_delta
      estimate < 0 ? 0_i64 : estimate
    end
  end
end
