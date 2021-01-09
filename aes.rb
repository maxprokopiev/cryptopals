require 'openssl'
require 'base64'
require './utils'

module AES
  include Utils

  def decrypt_aes_128_ecb(input, key)
    decipher = OpenSSL::Cipher.new('AES-128-ECB').decrypt
    decipher.key = key
    decipher.update(input)
  end

  def test_decrypt_aes_128_ecb
    input = Base64.decode64(File.read("./resources/aes_128_ecb.txt").split("\n").join)
    decrypt_aes_128_ecb(input, "YELLOW SUBMARINE")
  end

  def is_aes_128_ecb?(input)
    input.bytes.each_slice(16).reduce(Hash.new(0)) { |h, c| h[c] += 1; h }.values.uniq.size > 1
  end

  def detect_aes_128_ecb
    lines = File.read("./resources/detect_aes_ecb.txt").split("\n").map { |l| hex_to_str(l) }

    lines.select do |line|
      is_aes_128_ecb?(line)
    end
  end
end
