RSpec.describe Cryptopals::AES do
  include described_class

  describe "#aes_128_ctr" do
    it "de/encrypts in CTR mode" do
      input = Base64.decode64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
      key = "YELLOW SUBMARINE"
      expect(aes_128_ctr(input, key)).to eq "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    end
  end

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

  describe "#decrypt_aes_128_cbc" do
    it "decrypts AES 128 in CBC mode" do
      input = Base64.decode64(File.read("./spec/fixtures/aes_128_cbc.txt").split("\n").join)
      expect(decrypt_aes_128_cbc(input, "YELLOW SUBMARINE")).to include("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino")
    end
  end

  describe "EcbAttack" do
    it "decrypts 128 bit AES in ECB mode byte at a time" do
      expect(Cryptopals::AES::EcbAttack.new.decrypt).to eq "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    end
  end

  describe "EcbAttack2" do
    it "decrypts 128 bit AES in ECB mode byte at a time with random prefix" do
      expect(Cryptopals::AES::EcbAttack2.new.decrypt).to eq "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    end
  end
end
