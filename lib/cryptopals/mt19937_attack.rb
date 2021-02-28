module Cryptopals
  module MT19937Attack
    class Untemper
      include MT19937Contstants

      def call(value)
        y1 = value ^ (value >> L)

        y2 = y1 ^ ((y1 << T) & C)
        y3 = y2 ^ ((y2 << S) & 0x00001680)
        y4 = y3 ^ ((y3 << S) & 0x000c4000)
        y5 = y4 ^ ((y4 << S) & 0x0d200000)
        y6 = y5 ^ ((y5 << S) & 0x90000000)
        y7 = y6 ^ ((y6 >> U) & 0xffc00000)
        y8 = y7 ^ ((y7 >> U) & 0x003ff800)

        y8 ^ ((y8 >> U) & 0x000007ff)
      end

      def to_proc
        Proc.new { |v| call(v) }
      end
    end

    class TapGenerator
      include MT19937Contstants

      def call(generator)
        N.times.map do
          generator.extract_number
        end
      end
    end

    class Clone
      def call(generator)
        mt = TapGenerator.new.call(generator)

        MT19937.new(mt: mt.map(&Untemper.new))
      end
    end
  end
end
