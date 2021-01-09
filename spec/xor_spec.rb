RSpec.describe Cryptopals::Xor do
  include described_class

  describe "#xor" do
    it "xors two hex encoded strings" do
      s1 = hex_to_str("1c0111001f010100061a024b53535009181c").bytes
      s2 = hex_to_str("686974207468652062756c6c277320657965").bytes

      expect(arr_to_hex(xor(s1, s2))) == "746865206b696420646f6e277420706c6179"
    end
  end

  describe "#repeating_xor" do
    it "xors a given string with key repeatedly" do
      expect(arr_to_hex(repeating_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".bytes, "ICE".bytes))) == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    end
  end

  describe "#break_repeating_xor" do
    it "finds probable keys" do
      bytes = Base64.decode64(File.read("./spec/fixtures/repeating_xor.txt").split("\n").join).bytes

      expect(break_repeating_xor(bytes)).to include("Terminator X: Bring the noise")
    end
  end

  describe "#break_single_byte_xor" do
    it "detects key used in single-byte XOR" do
      expect(break_single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")).to eq "x"
    end
  end

  describe "#detect_single_char_xor" do
    it "detects single-byte xor" do
      input = File.read("./spec/fixtures/detect_single_char_xor.txt").split("\n")
      expect(detect_single_char_xor(input)).to eq ["Now that the party is jumping\n", "5", 224]
    end
  end
end
