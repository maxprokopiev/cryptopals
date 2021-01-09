module Cryptopals
  module Xor
    include Utils

    def xor(h1, h2)
      s1 = hex_to_str(h1)
      s2 = hex_to_str(h2)

      result = s1.bytes.zip(s2.bytes).map { |x, y| x ^ y }

      arr_to_hex(result)
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

    def detect_single_char_xor(lines)
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

    def break_repeating_xor(bytes)
      keysizes = probable_keysizes(bytes).take(3)
      probable_keys(bytes, keysizes)
    end

    def probable_keys(bytes, keysizes)
      keysizes.map do |keysize|
        transposed = bytes.each_slice(keysize).to_a[0..-2].transpose
        key = transposed.map do |block|
          ([" ", ",", ".", "!", "\n", ":", ";"] + ("0".."9").to_a + ("a".."z").to_a + ("A".."Z").to_a).map do |key|
            str = block.map { |e| e ^ key.bytes.first }.pack("c*")
            [key, en_score(str)]
          end.sort_by(&:last).last.first
        end.join
      end
    end

    def probable_keysizes(bytes, precision = 50)
      (2..40).map do |keysize|
        v = bytes.each_slice(keysize).take(precision).each_slice(2).map { |x, y| hamming_distance_bytes(x, y) / keysize.to_f }.sum / precision
        [keysize, v]
      end.sort_by(&:last).map(&:first)
    end
  end
end
