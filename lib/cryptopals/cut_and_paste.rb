module Cryptopals
  module CutAndPaste
    include AES

    class ProfileOracle
      def initialize
        @key = random_bytes(16).pack("c*")
      end

      def profile_for(email)
        raise Error.new if email =~ /&|=/

        input = profile(email)
        encrypt_aes_128_ecb(pad_input(input).pack("c*"), @key)
      end

      # "email=me@hacker." -> [104, 226, 59, 49, 190, 7, 217, 211, 208, 98, 52, 151, 185, 66, 74, 17]
      # "com&uid=10&role=" -> [216, 73, 121, 146, 131, 202, 201, 241, 186, 127, 173, 13, 205, 89, 180, 145]
      # "admin" with padding -> [210, 205, 159, 189, 247, 130, 178, 98, 67, 184, 83, 232, 166, 164, 220, 123]
      def decrypt_profile(input)
        result = decrypt_aes_128_ecb(input, @key)
        pad_byte = result[-1].bytes.first
        if pad_byte < 16 then
          result[0..(-pad_byte - 1)]
        else
          result
        end
      end

      private

      # email=foo@bar.com&uid=10&role=user
      def profile(email)
        params = {
          email: email,
          uid: 10,
          role: "user"
        }
        "email=" + params[:email] + "&uid=" + params[:uid].to_s + "&role=" + params[:role]
      end

      def pad_input(input)
        if input.size > 16 then
          pkcs7(input.bytes, ((input.size / 16) + 1) * 16)
        else
          pkcs7(input.bytes, 16)
        end
      end
    end
  end
end
