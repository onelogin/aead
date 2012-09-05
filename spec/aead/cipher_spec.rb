require 'spec_helper'

require 'aead/cipher'

describe AEAD::Cipher do
  subject { cipher(self.algo, self.key, self.nonce, self.aad) }

  let(:algo)      { 'aes-256-gcm' }
  let(:key)       { AEAD.generate_key_256_bits }
  let(:nonce)     { AEAD.generate_nonce }
  let(:aad)       { SecureRandom.random_bytes }
  let(:plaintext) { 'plaintext' }

  def cipher(algo, key, nonce, aad)
    AEAD::Cipher.new(algo, key, nonce, aad)
  end

  def do_encryption(cipher, plaintext)
    cipher.encrypt do |cipher|
      [ cipher.update(plaintext) + cipher.final, cipher.gcm_tag ]
    end
  end

  def do_decryption(cipher, ciphertext, tag)
    cipher.decrypt(tag) do |cipher|
      cipher.update(ciphertext) + cipher.verify
    end
  end

  def twiddle(bytes)
    index = SecureRandom.random_number(bytes.bytesize)
    byte  = SecureRandom.random_bytes(1)

    bytes[0..index.pred] << byte << bytes[index.succ..-1]
  end

  it 'must produce a tag on encryption' do
    ciphertext, tag = do_encryption(self.subject, self.plaintext)

    tag         .must_be :kind_of?, String
    tag.bytesize.must_equal 16
  end

  it 'must verify legitimate tags during decryption' do
    ciphertext, tag = do_encryption(self.subject, self.plaintext)
    plaintext       = do_decryption(self.subject, ciphertext, tag)

    plaintext.must_equal self.plaintext
  end

  it 'must raise an exception when the ciphertext has been manipulated' do
    ciphertext, tag = do_encryption(self.subject, self.plaintext)

    -> { do_decryption self.subject, twiddle(ciphertext), tag }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the tag has been manipulated' do
    ciphertext, tag = do_encryption(self.subject, self.plaintext)

    -> { do_decryption self.subject, ciphertext, twiddle(tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the key has been manipulated' do
    ciphertext, tag = do_encryption(self.subject, self.plaintext)
    decryptor       = cipher(self.algo, twiddle(self.key), self.nonce, self.aad)

    -> { do_decryption(decryptor, ciphertext, tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the nonce has been manipulated' do
    ciphertext, tag = do_encryption(self.subject, self.plaintext)
    decryptor       = cipher(self.algo, self.key, twiddle(self.nonce), self.aad)

    -> { do_decryption(decryptor, ciphertext, tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the AAD has been manipulated' do
    ciphertext, tag = do_encryption(self.subject, self.plaintext)
    decryptor       = cipher(self.algo, self.key, self.nonce, twiddle(self.aad))

    -> { do_decryption(decryptor, ciphertext, tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must require the nonce to be at least twelve bytes' do
    [0, 1, 11].map {|count| SecureRandom.random_bytes(count) }.each do |nonce|
      -> { cipher(self.algo, self.key, nonce, self.aad) }.
        must_raise ArgumentError
    end
  end
end
