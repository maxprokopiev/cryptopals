module Cryptopals
  module CbcPaddingOracle
    include AES

    class PaddingOracle
      def initialize
        @key = random_bytes(16).pack("c*")
      end

      def encrypt
        iv = random_iv
        sample = pad_input(Base64.decode64(samples.sample)).pack("c*")

        [
          encrypt_aes_128_cbc(sample, @key, iv),
          iv
        ]
      end

      def decrypt(input, iv)
        strip_pkcs7(decrypt_aes_128_cbc(input, @key, iv).bytes)
        true
      rescue StandardError
        false
      end

      def random_iv
        random_bytes(16)
      end

      def samples
        %w[
            MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
            MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
            MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
            MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
            MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
            MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
            MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
            MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
            MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
            MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
        ]
      end

      def pad_input(input)
        if input.size > 16 then
          pkcs7(input.bytes, ((input.size / 16) + 1) * 16)
        else
          pkcs7(input.bytes, 16)
        end
      end
    end

    class PaddingOracleAttack
      def initialize(po = PaddingOracle.new)
        @po = po
      end

      def attack
        ciphertext, iv = @po.encrypt
        blocks = ciphertext.bytes.each_slice(16).to_a

        blocks.zip([iv] + blocks).reduce("") do |acc, e|
          acc + decrypt(e[1], e[0], iv)
        end
      end

      def decrypt(c1, c2, iv)
        d = []
        p = []

        (1..16).each do |i|
          c1_1 = c1.dup
          (1..(i - 1)).each { |j| c1_1[-j] = d[-j] ^ i }
          byte = find_byte(c1_1.dup, c2.dup, iv, -i)
          d.prepend(byte ^ i)
          p.prepend(d[-i] ^ c1[-i])
        end

        p.pack("c*")
      end

      def find_byte(c1, c2, iv, i, byte = 0)
        raise Error.new if byte > 255

        c1[-2] = rand(256) if i == -1
        c1[i] = byte
        if @po.decrypt((c1 + c2).pack("c*"), iv) then
          byte
        else
          find_byte(c1, c2, iv, i, byte + 1)
        end
      end
    end
  end
end
