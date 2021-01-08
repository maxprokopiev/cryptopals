require './utils'

module Xor
  include Utils

  def xor(h1, h2)
    s1 = hex_to_str(h1)
    s2 = hex_to_str(h2)

    result = s1.bytes.zip(s2.bytes).map { |x, y| x ^ y }

    result.map { |e| e.to_s(16) }.join
  end

  def test
    xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"
  end
end
