RSpec.describe Cryptopals::Utils do
  include described_class

  describe "#hex_to_str" do
    it "converts hex encoded string to normal string" do
      expect(hex_to_str("686974207468652062756c6c277320657965")).to eq "hit the bull's eye"
    end
  end

  describe "#pkcs7" do
    it "pads any block to a specific block length, by appending the number of bytes of padding to the end of the block" do
      s = "YELLOW SUBMARINE".bytes
      expect(pkcs7(s, 20).pack("c*")).to eq "YELLOW SUBMARINE\x04\x04\x04\x04"
    end
  end
end
