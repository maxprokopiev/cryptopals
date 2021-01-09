require 'openssl'
require 'base64'

module AES
  def decrypt_aes_128_ecb(input, key)
    decipher = OpenSSL::Cipher.new('AES-128-ECB').decrypt
    decipher.key = key
    decipher.update(input)
  end

  def test_decrypt_aes_128_ecb
    input = Base64.decode64(File.read("./resources/aes_128_ecb.txt").split("\n").join)
    decrypt_aes_128_ecb(input, "YELLOW SUBMARINE")
  end
end
