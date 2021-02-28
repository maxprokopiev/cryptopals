RSpec.describe Cryptopals::MT19937Attack::Clone do
  describe "#call" do
    it 'clones the given generator from it\'s output' do
      mt = Cryptopals::MT19937.new
      clone = Cryptopals::MT19937Attack::Clone.new

      mt_cloned = clone.call(mt)

      624.times do
        expect(mt.extract_number).to eq(mt_cloned.extract_number)
      end
    end
  end
end
