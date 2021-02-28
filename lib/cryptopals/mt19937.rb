module Cryptopals
  module MT19937Contstants
    W = 32
    N = 624
    M = 397
    R = 31
    A = "9908B0DF".to_i(16)
    U = 11
    D = "FFFFFFFF".to_i(16)
    S = 7
    B = "9D2C5680".to_i(16)
    T = 15
    C = "EFC60000".to_i(16)
    L = 18
    F = 1812433253
  end

  class MT19937
    include MT19937Contstants

    def initialize(mt: nil, seed_value: 5489)
      @mask = 2**W - 1
      @index = N + 1
      @lower_mask = (1 << R) - 1
      @upper_mask = (~@lower_mask) & @mask

      if mt == nil
        @mt = []
        seed(seed_value)
      else
        @mt = mt
        @index = N
      end
    end

    def extract_number
      if @index >= N then
        if @index > N then
          raise "Generator was never seeded"
        end

        twist
      end

      y = @mt[@index]
      y = y ^ ((y >> U) & D)
      y = y ^ ((y << S) & B)
      y = y ^ ((y << T) & C)
      y = y ^ (y >> L)

      @index += 1

      y & @mask
    end

    private

    def seed(value)
      @index = N
      @mt[0] = value
      (1..(N - 1)).each { |i| @mt[i] = (F * (@mt[i - 1] ^ (@mt[i - 1] >> (W - 2))) + i) & @mask }
    end


    def twist
      (0..(N - 1)).each do |i|
        x = (@mt[i] & @upper_mask) + (@mt[(i + 1) % N] & @lower_mask)
        xA = x >> 1
        xA = xA ^ A if x % 2 != 0
        @mt[i] = @mt[(i + M) % N] ^ xA
      end

      @index = 0
    end
  end
end
