RSpec.describe Cryptopals::MT19937 do
  describe "#extract_number" do
    it "generates the same sequence with the same seed value" do
      mt = described_class.new(seed_value: 1)
      s1 = []
      (0..10).each { s1 << mt.extract_number }

      mt = described_class.new(seed_value: 1)
      s2 = []
      (0..10).each { s2 << mt.extract_number }

      expect(s1).to eq(s2)

      expect(s1).to eq([1791095845, 4282876139, 3093770124, 4005303368, 491263, 550290313, 1298508491, 4290846341, 630311759, 1013994432, 396591248])
    end
  end
end
