require 'openssl'
require 'base64'

module Cryptopals
  module AES
    include Utils
    include Xor

    def decrypt_aes_128_cbc(input, key)
      iv = [0]*16
      input.bytes.each_slice(16).reduce([iv, ""]) do |(prev, r), block|
        [
          block,
          r + xor(decrypt_aes_128_ecb(pkcs7(block, 16).pack("c*"), key).bytes, prev).pack("c*")
        ]
      end.last
    end

    def encrypt_aes_128_ecb(input, key)
      aes_128_ecb(:encrypt, input, key)
    end

    def decrypt_aes_128_ecb(input, key)
      aes_128_ecb(:decrypt, input, key)
    end

    def is_aes_128_ecb?(input)
      input.bytes.each_slice(16).reduce(Hash.new(0)) { |h, c| h[c] += 1; h }.values.uniq.size > 1
    end

    def detect_aes_128_ecb(lines)
      lines.select do |line|
        is_aes_128_ecb?(line)
      end
    end

    private

    def aes_128_ecb(action, input, key)
      cipher = OpenSSL::Cipher.new('AES-128-ECB').send(action)
      cipher.key = key
      cipher.padding = 0
      cipher.update(input) + cipher.final
    end
  end
end
