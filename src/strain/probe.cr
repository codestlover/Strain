require "socket"
require "./packet"
require "./socks5"

module Strain
  # One-shot send-and-classify of a single mutated ConnectRequest. Used for
  # cold/hot/post pulse probes that frame the verdict.
  module Probe
    REJECT_NAMES = {
      0x02_u8 => "InvalidToken",
      0x04_u8 => "KickedFromHost",
      0x06_u8 => "ConnectFailed",
      0x09_u8 => "PeerNotFound",
      0x0c_u8 => "NotPermitted",
      0x0d_u8 => "Challenge",
      0x0e_u8 => "PeerNotFound",
      0x0f_u8 => "InvalidProtocol",
      0x11_u8 => "Banned",
      0x13_u8 => "VerificationFailed",
    }

    record Result, rtt_ms : Float64, label : String, reject_code : UInt8?, length : Int32

    def self.fmt_response(data : Bytes?) : {String, UInt8?}
      return {"silent", nil} unless data
      return {"silent(0B)", nil} if data.empty?
      first = data[0]
      if first == 0x07_u8 && data.size > 9
        code = data[9]
        name = REJECT_NAMES[code]? || sprintf("0x%02x", code)
        return {"Disc/#{name}", code}
      end
      if first == 0x06_u8
        return {"ConnectAccept(#{data.size}B)", first}
      end
      if name = REJECT_NAMES[first]?
        return {name, first}
      end
      {sprintf("prop=0x%02x(%dB)", first, data.size), first}
    end

    # Send one mutated ConnectRequest and wait up to `timeout` for a reply.
    def self.shot(target : Target, *, timeout : Time::Span = 2.seconds,
                  socket : UDPSocket? = nil,
                  proxy_pool : Socks5::Pool? = nil) : Result
      owns_socket = socket.nil?
      probe_socket = socket
      buf = Packet.scratch
      Packet.mutate!(buf, Random.new)
      t0 = Time.monotonic
      session = nil
      begin
        if pool = proxy_pool
          session = pool.open(target)
          session.send(buf)
          rbuf = Bytes.new(2048)
          n = session.receive(rbuf)
          elapsed = (Time.monotonic - t0).total_milliseconds
          if n
            reply = rbuf[0, n]
            label, code = fmt_response(reply)
            return Result.new(elapsed, label, code, reply.size)
          end
          return Result.new(elapsed, "silent", nil, 0)
        end

        if probe_socket.nil?
          probe_socket = UDPSocket.new
          probe_socket.bind "0.0.0.0", 0
        end
        s = probe_socket.not_nil!
        s.read_timeout = timeout
        s.send(buf, to: Socket::IPAddress.new(target.host, target.port))
        rbuf = Bytes.new(2048)
        n, _ = s.receive(rbuf)
        reply = rbuf[0, n]
        elapsed = (Time.monotonic - t0).total_milliseconds
        label, code = fmt_response(reply)
        Result.new(elapsed, label, code, reply.size)
      rescue IO::TimeoutError
        Result.new((Time.monotonic - t0).total_milliseconds, "silent", nil, 0)
      rescue ex : IO::Error | Socket::Error
        Result.new((Time.monotonic - t0).total_milliseconds, "probe-error(#{ex.class})", nil, 0)
      ensure
        session.try &.close rescue nil
        if owns_socket
          probe_socket.try &.close rescue nil
        end
      end
    end
  end
end
