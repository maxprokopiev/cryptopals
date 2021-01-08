require 'base64'

module Utils
  MOST_FREQUENT_LETTERS_EN = %w[e t a o i n s h]

  def hex_to_base64(s)
    Base64.strict_encode64(hex_to_str(s))
  end

  def hex_to_str(s)
    # TODO: e.first ??
    s.scan(/../).map { |e| e.to_i(16) }.pack("c*")
  end

  def arr_to_hex(a)
    a.map { |e| e.to_s(16).rjust(2, "0") }.join
  end

  def frequencies(s)
    s.downcase.scan(/./).reduce(Hash.new(0)) { |h, c| h[c] += 1; h }
  end

  def en_score(s)
    letters = ("0".."9").to_a + ("a".."z").to_a

    frequencies(s).reduce(0) do |score, (c, f)|
      score += f if letters.include?(c)
      score += f*10 if MOST_FREQUENT_LETTERS_EN.include?(c)
      score
    end
  end
end
