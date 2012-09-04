require 'spec_helper'

require 'aead/cipher'

describe AEAD::Cipher do
  subject do
    AEAD::Cipher.new('aes-256-gcm', self.key, self.nonce, self.aad)
  end

  let(:key)       { AEAD.generate_key_256_bits }
  let(:nonce)     { AEAD.generate_nonce }
  let(:aad)       { SecureRandom.random_bytes }
  let(:plaintext) { 'plaintext' }

  def do_encryption(plaintext)
    subject.encrypt do |cipher|
      [ cipher.update(plaintext) + cipher.final, cipher.gcm_tag ]
    end
  end

  def do_decryption(ciphertext, tag)
    subject.decrypt(tag) do |cipher|
      cipher.update(ciphertext) + cipher.verify
    end
  end

  def twiddle(bytes)
    index = SecureRandom.random_number(bytes.bytesize)
    byte  = SecureRandom.random_bytes(1)

    bytes[0..index.pred] << byte << bytes[index.succ..-1]
  end

  it 'must produce a tag on encryption' do
    ciphertext, tag = do_encryption(self.plaintext)

    tag         .must_be :kind_of?, String
    tag.bytesize.must_equal 16
  end

  it 'must verify legitimate tags during decryption' do
    ciphertext, tag = do_encryption(self.plaintext)
    plaintext       = do_decryption(ciphertext, tag)

    plaintext.must_equal self.plaintext
  end

  it 'must raise an exception when the ciphertext has been manipulated' do
    ciphertext, tag = do_encryption(self.plaintext)

    -> { do_decryption twiddle(ciphertext), tag }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the tag has been manipulated' do
    ciphertext, tag = do_encryption(self.plaintext)

    -> { do_decryption ciphertext, twiddle(tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the key has been manipulated' do
    ciphertext, tag = do_encryption(self.plaintext)

    self.subject.send(:key=, AEAD.generate_key_256_bits)

    -> { do_decryption(ciphertext, tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the nonce has been manipulated' do
    ciphertext, tag = do_encryption(self.plaintext)

    self.subject.send(:nonce=, AEAD.generate_nonce)

    -> { do_decryption(ciphertext, tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end

  it 'must raise an exception when the AAD has been manipulated' do
    ciphertext, tag = do_encryption(self.plaintext)

    self.subject.send :aad=, twiddle(self.aad)

    -> { do_decryption(ciphertext, tag) }.
      must_raise OpenSSL::Cipher::CipherError
  end
end
