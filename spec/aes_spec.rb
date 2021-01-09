RSpec.describe Cryptopals::AES do
  include described_class

  describe "#decrypt_aes_128_ecb" do
    it "decrypts AES 128 in ECB mode" do
      input = Base64.decode64(File.read("./spec/fixtures/aes_128_ecb.txt").split("\n").join)
      expect(decrypt_aes_128_ecb(input, "YELLOW SUBMARINE")).to include("Well that's my DJ Deshay cuttin' all them Z's")
    end
  end

  describe "#detect_aes_128_ecb" do
    it "detects AES in ECB mode" do
      input = File.read("./spec/fixtures/detect_aes_ecb.txt").split("\n").map { |l| hex_to_str(l) }
      expect(arr_to_hex(detect_aes_128_ecb(input).first.bytes)).to eq "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    end
  end
end
