require 'base64'

module Cryptopals
  module Utils
    MOST_FREQUENT_LETTERS_EN = %w[e t a o i n s h]

    def hex_to_base64(s)
      Base64.strict_encode64(hex_to_str(s))
    end

    def hex_to_str(s)
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
        score += f*10 if (MOST_FREQUENT_LETTERS_EN + [" ", ",", ".", "!", "\n", ":", ";"]).include?(c)
        score
      end
    end

    def bits(s)
      s.each_byte.map { |b| b.to_s(2).rjust(8, "0") }.join.scan(/./).map(&:to_i)
    end

    def hamming_distance(s1, s2)
      bits(s1).zip(bits(s2)).count { |x, y| x != y }
    end

    def bits_bytes(s)
      s.map { |b| b.to_s(2).rjust(8, "0") }.join.scan(/./).map(&:to_i)
    end

    def hamming_distance_bytes(s1, s2)
      bits_bytes(s1).zip(bits_bytes(s2)).count { |x, y| x != y }
    end
  end
end
