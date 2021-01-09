RSpec.describe Cryptopals::Utils do
  include described_class

  describe "#hex_to_str" do
    it "converts hex encoded string to normal string" do
      expect(hex_to_str("686974207468652062756c6c277320657965")).to eq "hit the bull's eye"
    end
  end
end
