require './utils'

module Xor
  include Utils

  def xor(h1, h2)
    s1 = hex_to_str(h1)
    s2 = hex_to_str(h2)

    result = s1.bytes.zip(s2.bytes).map { |x, y| x ^ y }

    arr_to_hex(result)
  end

  def test
    xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"
  end

  def single_byte_xor(s, key)
    s.bytes.map { |e| e ^ key }
  end

  def break_single_byte_xor(s)
    with_max_score(s)[1]
  end

  def with_max_score(s)
    s = hex_to_str(s)
    (("0".."9").to_a + ("a".."z").to_a).map do |key|
      str = single_byte_xor(s, key.bytes.first).pack("c*")
      [str, key, en_score(str)]
    end.sort_by(&:last).last
  end

  def test_single_byte_xor
    break_single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
  end

  def detect_single_char_xor
    lines = File.read("./resources/detect_single_char_xor.txt").split("\n")
    lines.map do |l|
      with_max_score(l)
    end.sort_by(&:last).last
  end

  def repeating_xor(str, key)
    key = key.bytes
    j = -1
    str.bytes.each_with_index.map do |c, i|
      j = (j + 1) % key.size
      c ^ key[j]
    end
  end

  def test_repeating_xor
    arr_to_hex(repeating_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")) == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
  end
end
