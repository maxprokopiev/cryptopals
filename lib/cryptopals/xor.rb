module Cryptopals
  module Xor
    include Utils

    def xor(b1, b2)
      b1.zip(b2).map { |x, y| x ^ y }
    end

    def single_byte_xor(bytes, key)
      bytes.map { |e| e ^ key }
    end

    def break_single_byte_xor(s)
      with_max_score(s)[1]
    end

    def with_max_score(s)
      s = hex_to_str(s)
      (("0".."9").to_a + ("a".."z").to_a).map do |key|
        str = single_byte_xor(s.bytes, key.bytes.first).pack("c*")
        [str, key, en_score(str)]
      end.sort_by(&:last).last
    end

    def detect_single_char_xor(lines)
      lines.map do |l|
        with_max_score(l)
      end.sort_by(&:last).last
    end

    def repeating_xor(bytes, key)
      j = -1
      bytes.map do |c|
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
        v = bytes.each_slice(keysize).take(precision).each_slice(2).map { |x, y| hamming_distance(x, y) / keysize.to_f }.sum / precision
        [keysize, v]
      end.sort_by(&:last).map(&:first)
    end
  end
end
