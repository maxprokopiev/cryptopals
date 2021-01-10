module Cryptopals
  module CtrSubstitutions
    include AES

    SAMPLES = %w[
      SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
      Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
      RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
      RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
      SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
      T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
      T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
      UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
      QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
      T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
      VG8gcGxlYXNlIGEgY29tcGFuaW9u
      QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
      QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
      QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
      QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
      QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
      VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
      SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
      SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
      VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
      V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
      V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
      U2hlIHJvZGUgdG8gaGFycmllcnM/
      VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
      QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
      VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
      V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
      SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
      U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
      U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
      VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
      QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
      SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
      VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
      WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
      SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
      SW4gdGhlIGNhc3VhbCBjb21lZHk7
      SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
      VHJhbnNmb3JtZWQgdXR0ZXJseTo=
      QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
    ]

    ALPHABET = ("A".."Z").to_a + ("a".."z").to_a + [" ", ":", ",", ".", ";", "'", "-", "&", "%", "$", "^", "=", "\n"]
    EN_TRIGRAMS = %w[the and ing her hat his tha ere for ent ion ter was you ith ver all wit thi tio]

    def possible_bytes_at(bytes, alphabet, i)
      (0..255).select do |byte|
        r = bytes.map { |e| e[i] }.compact.map { |e| [e ^ byte].pack("c*") }
        r.all? { |e| alphabet.include?(e) }
      end
    end

    def possible_keystreams(cipherbytes, x1, x2, x3, x4)
      b1s = possible_bytes_at(cipherbytes, ALPHABET, x1)
      b2s = possible_bytes_at(cipherbytes, ALPHABET, x2)
      b3s = possible_bytes_at(cipherbytes, ALPHABET, x3)
      b4s = possible_bytes_at(cipherbytes, ALPHABET, x4)

      pks = []
      b1s.each do |b1|
        b2s.each do |b2|
          b3s.each do |b3|
            b4s.each do |b4|
              pts = cipherbytes.select { |bytes| bytes.size >= x4 }.map { |bytes| xor(bytes.drop(x1).take(4), [b1, b2, b3, b4]).pack("c*") }
              count = pts.count { |s| EN_TRIGRAMS.count { |tri| s.downcase.include?(tri) } > 0 }
              pks << [count, [b1, b2, b3, b4]] if count > 0
            end
          end
        end
      end
      pks
    end

    def encrypt
      key = random_bytes(16).pack("c*")
      ciphertexts = SAMPLES.map { |s| aes_128_ctr(Base64.decode64(s), key) }

      cipherbytes = ciphertexts.map(&:bytes)
      b1s = possible_bytes_at(cipherbytes, ("A".."Z").to_a, 0)
      b2s = possible_bytes_at(cipherbytes, ALPHABET, 1)
      b3s = possible_bytes_at(cipherbytes, ALPHABET, 2)
      b4s = possible_bytes_at(cipherbytes, ALPHABET, 3)
      b5s = possible_bytes_at(cipherbytes, ALPHABET, 4)
      b6s = possible_bytes_at(cipherbytes, ALPHABET, 5)

      pks = []
      b1s.each do |b1|
        b2s.each do |b2|
          b3s.each do |b3|
            b4s.each do |b4|
              b5s.each do |b5|
                b6s.each do |b6|
                  pts = cipherbytes.map { |bytes| xor(bytes.take(6), [b1, b2, b3, b4, b5, b6]).pack("c*") }
                  count = pts.count { |s| EN_TRIGRAMS.count { |tri| s.downcase.include?(tri) } > 0 }
                  pks << [count, [b1, b2, b3, b4, b5, b6]] if count > 13
                end
              end
            end
          end
        end
      end
      keystream = pks.first.last

      bts = cipherbytes.select { |bytes| bytes.length > 22 }
      (6..(bts.map(&:size).max)).each_slice(4) do |x1, x2, x3, x4|
        c, keystream_bytes = possible_keystreams(bts, x1, x2, x3, x4).max { |x, y| x.first <=> y.first }
        keystream += keystream_bytes
        decrypt(bts, keystream)
        puts "="*100
      end
    end

    def decrypt(cipherbytes, keystream_bytes)
      cipherbytes.map do |bytes|
        puts xor(bytes.take(keystream_bytes.size), keystream_bytes.take(bytes.size)).pack("c*").inspect
      end;0
    end
  end
end
