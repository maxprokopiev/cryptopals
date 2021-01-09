require 'openssl'
require 'base64'

module Cryptopals
  module AES
    include Utils
    include Xor

    class ConstantKeyECB
      include AES

      def initialize(with_prefix = false)
        @key = random_bytes(16).pack("c*")
        @with_prefix = with_prefix
        @prefix = random_bytes(rand(100)).pack("c*")
        @input = Base64.decode64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
      end

      def encrypt(input)
        input = if @with_prefix
          pad_input(@prefix + input + @input).pack("c*")
        else
          pad_input(input + @input).pack("c*")
        end

        encrypt_aes_128_ecb(input, @key)
      end

      def pad_input(input)
        if input.size > 16 then
          pkcs7(input.bytes, ((input.size / 16) + 1) * 16)
        else
          pkcs7(input.bytes, 16)
        end
      end
    end

    class EcbAttack2
      include AES

      def initialize(cipher = ConstantKeyECB.new(true))
        @cipher = cipher
        @block_size = 16
      end

      def decrypt
        pad_length, start_block = random_prefix_length
        pre_processor = Proc.new do |input|
          ("A" * pad_length) + input
        end
        post_processor = Proc.new do |output|
          output.bytes.drop(start_block * @block_size).pack("c*")
        end
        EcbAttack.new(@cipher, post_processor, pre_processor).decrypt
      end

      def sample_block_ciphertext
        return @sample_block_ciphertext if @sample_block_ciphertext

        blocks = @cipher.encrypt(("A"*@block_size)*3).bytes.each_slice(@block_size).to_a
        @sample_block_ciphertext = blocks.zip(blocks[1..-1]).find { |b1, b2| b1 == b2 }[0]
      end

      def random_prefix_length(i = 0)
        blocks = @cipher.encrypt("A"*i + "A"*@block_size).bytes.each_slice(@block_size).to_a

        index = blocks.index(sample_block_ciphertext)
        if index
          [i, index]
        else
          random_prefix_length(i + 1)
        end
      end
    end

    class EcbAttack
      include AES

      def initialize(cipher = ConstantKeyECB.new, post_processor = Proc.new { |e| e }, pre_processor = Proc.new { |e| e })
        @cipher = cipher
        @block_size = 16 # block_size
        @post_processor = post_processor
        @pre_processor = pre_processor
      end

      def encrypt(input)
        @post_processor.call(@cipher.encrypt(@pre_processor.call(input)))
      end

      def decrypt(round = 0, block_num = 1, result = "")
        ciphertext = encrypt("A" * (@block_size - 1 - round))
        matching_samples = samples(@block_size - round, result).find { |k, v| v[0..((@block_size - 1)*block_num - 1)] == ciphertext[0..((@block_size - 1)*block_num - 1)] }
        next_char = if matching_samples then
                      matching_samples.first[-1]
                    else
                      return result[0..-2]
                    end

        block_num += 1 if (round + 1) % @block_size == 0
        decrypt((round + 1) % @block_size, block_num, result + next_char)
      end

      def samples(size, postfix)
        prefix = "A" * (size - 1) + postfix
        pairs = (0..255).map do |byte|
          input = prefix + [byte].pack("c*")
          [input, encrypt(input)]
        end

        Hash[*pairs.flatten]
      end

      def mode
        DetectionOracle.new(@cipher).detect_mode
      end

      def block_size(size = 1, previous = [])
        block = @cipher.encrypt("A"*size).bytes.each_slice(size).to_a.first
        if (previous != []) && (previous == block[0..-2])
          size - 1
        else
          block_size(size + 1, block)
        end
      end
    end

    class EncryptionOracle
      include AES

      def initialize
        @mode = rand(2) == 1 ? :ecb : :cbc
      end

      def encrypt(input)
        randomized_input = randomize_input(input)

        if @mode == :ecb then
          encrypt_aes_128_ecb(randomized_input.pack("c*"), random_key)
        else
          encrypt_aes_128_cbc(randomized_input.pack("c*"), random_key, random_iv)
        end
      end

      private

      def randomize_input(input)
        randomized_input = random_bytes(10).take(rand(6) + rand(6)) + input.bytes + random_bytes(10).take(rand(6) + rand(6))
        if randomized_input.size > 16 then
          pkcs7(randomized_input, ((randomized_input.size / 16) + 1) * 16)
        else
          pkcs7(randomized_input, 16)
        end
      end

      def random_iv
        random_bytes(16)
      end

      def random_key
        random_bytes(16).pack("c*")
      end
    end

    class DetectionOracle
      include AES

      def initialize(encryption_oracle)
        @encryption_oracle = encryption_oracle
        @sample_input = ([0]*100).pack("c*")
      end

      def detect_mode
        _, x, y = @encryption_oracle.encrypt(@sample_input).bytes.each_slice(16).take(3)
        x == y ? :ecb : :cbc
      end
    end

    def decrypt_aes_128_cbc(input, key, iv = [0]*16)
      input.bytes.each_slice(16).reduce([iv, ""]) do |(prev, r), block|
        [
          block,
          r + xor(decrypt_aes_128_ecb(pkcs7(block, 16).pack("c*"), key).bytes, prev).pack("c*")
        ]
      end.last
    end

    def encrypt_aes_128_cbc(input, key, iv = [0]*16)
      input.bytes.each_slice(16).reduce([iv, ""]) do |(prev, r), block|
        new_block = encrypt_aes_128_ecb(xor(pkcs7(block, 16), prev).pack("c*"), key).bytes
        [
          new_block,
          r + new_block.pack("c*")
        ]
      end.last
    end

    def encrypt_aes_128_ecb(input, key)
      aes_128_ecb(:encrypt, input, key)
    end

    def decrypt_aes_128_ecb(input, key)
      aes_128_ecb(:decrypt, input, key)
    end

    def is_aes_128_ecb?(input)
      freqs = input.bytes.each_slice(16).reduce(Hash.new(0)) { |h, c| h[c] += 1; h }.values.uniq
      (freqs.size > 1) && (freqs.any? { |e| e > 2 })
    end

    def detect_aes_128_ecb(lines)
      lines.select do |line|
        is_aes_128_ecb?(line)
      end
    end

    def random_bytes(size = 16)
      (0..(size - 1)).map { |_| rand(255) }
    end

    private

    def aes_128_ecb(action, input, key)
      cipher = OpenSSL::Cipher.new('AES-128-ECB').send(action)
      cipher.key = key
      cipher.padding = 0
      cipher.update(input) + cipher.final
    end
  end
end
