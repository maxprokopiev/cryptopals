require 'base64'

module Utils
  def hex_to_base64(s)
    Base64.strict_encode64(hex_to_str(s))
  end

  def hex_to_str(s)
    s.scan(/(..)/).map { |e| e.first.to_i(16) }.pack("c*")
  end

  def test
    input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    hex_to_base64(input) == result
  end
end
