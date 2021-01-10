module Cryptopals
  module CbcBitFlipping
    include AES

    class CookieOracle
      def initialize
        @key = random_bytes(16).pack("c*")
      end

      def cookie_for(user_data)
        input = pad_input("comment1=cooking%20MCs;userdata=" + sanitize(user_data) + ";comment2=%20like%20a%20pound%20of%20bacon")

        encrypt_aes_128_cbc(input.pack("c*"), @key)
      end

      def is_admin?(ciphertext)
        decrypt_aes_128_cbc(ciphertext, @key).include?(";admin=true;")
      end

      def sanitize(user_data)
        user_data.gsub(/;/, "%3B").gsub(/=/, "%3D")
      end

      def pad_input(input)
        if input.size > 16 then
          pkcs7(input.bytes, ((input.size / 16) + 1) * 16)
        else
          pkcs7(input.bytes, 16)
        end
      end
    end

    class BitFlippingAttack
      def initialize(co = CookieOracle.new)
        @co = co
      end

      def attack
        blocks = @co.cookie_for(user_data).bytes.each_slice(16).to_a
        blocks[2] = modified_block

        @co.is_admin?(blocks.flatten.pack("c*"))
      end

      def user_data
        "A"*16 + "AAAAA:admin<true"
      end

      def modified_block
        block = @co.cookie_for("A"*16).bytes.each_slice(16).to_a[2]

        block[5] = block[5] ^ 1
        block[11] = block[11] ^ 1

        block
      end
    end
  end
end
