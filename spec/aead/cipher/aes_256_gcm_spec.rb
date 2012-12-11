require 'spec_helper'
require 'aead/cipher/aes_256_gcm'

describe AEAD::Cipher::AES_256_GCM do
  subject { self.cipher.new(self.key) }

  let(:algo)      { 'aes-256-gcm' }
  let(:cipher)    { AEAD::Cipher.new(algo) }
  let(:key)       { self.cipher.generate_key }
  let(:nonce)     { self.cipher.generate_nonce }
  let(:aad)       { SecureRandom.random_bytes }
  let(:plaintext) { SecureRandom.random_bytes }

  it 'must decrypt its own ciphertexts' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    plaintext  = subject.decrypt(self.nonce, self.aad, ciphertext)

    plaintext.must_equal self.plaintext
  end

  it 'must require a 256-bit or larger key' do
    bad_keys  = [  0,  1,  31 ].map {|size| SecureRandom.random_bytes(size) }
    good_keys = [ 32, 33, 256 ].map {|size| SecureRandom.random_bytes(size) }

    bad_keys.each do |key|
      lambda { self.cipher.new(key) }.must_raise ArgumentError
    end

    good_keys.each do |key|
      self.cipher.new(key).must_be_kind_of AEAD::Cipher
    end
  end

  it 'must require a 12-byte nonce' do
    bad_nonces  = [0, 1, 11, 13 ].map {|size| SecureRandom.random_bytes(size) }
    good_nonces = [ 12 ]         .map {|size| SecureRandom.random_bytes(size) }

    bad_nonces.each do |nonce|
      lambda { self.subject.encrypt(nonce, self.plaintext, self.aad) }.
        must_raise ArgumentError
    end

    good_nonces.each do |nonce|
      self.subject.encrypt(nonce, self.plaintext, self.aad).
        must_be_kind_of String
    end
  end

  it 'must require a non-empty plaintext' do
    lambda { self.subject.encrypt(nonce, self.aad, nil) }.must_raise ArgumentError
    lambda { self.subject.encrypt(nonce, self.aad,  '') }.must_raise ArgumentError
  end

  it 'must encrypt plaintexts correctly' do
    subject.encrypt(self.nonce, self.aad, self.plaintext).
      must_equal openssl_encrypt(self.key, self.nonce, self.aad, self.plaintext)
  end

  it 'must decrypt ciphertexts correctly' do
    ciphertext = openssl_encrypt(self.key, self.nonce, self.aad, self.plaintext)

    subject.decrypt(self.nonce, self.aad, ciphertext).
      must_equal openssl_decrypt(self.key, self.nonce, self.aad, ciphertext)
  end

  it 'must resist manipulation of the key' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    cipher     = self.cipher.new twiddle(key)

    lambda { cipher.decrypt(self.nonce, self.aad, ciphertext) }.
      must_raise ArgumentError
  end

  it 'must resist manipulation of the nonce' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    nonce      = twiddle(self.nonce)

    lambda { self.subject.decrypt(nonce, self.aad, ciphertext) }.
      must_raise ArgumentError
  end

  it 'must resist manipulation of the ciphertext' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    ciphertext = twiddle(ciphertext)

    lambda { self.subject.decrypt(self.nonce, self.aad, ciphertext) }.
      must_raise ArgumentError
  end

  it 'must resist manipulation of the aad' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    aad        = twiddle(self.aad)

    lambda { self.subject.decrypt(self.nonce, aad, ciphertext) }.
      must_raise ArgumentError
  end

  def twiddle(bytes)
    # pick a random byte to change
    index  = SecureRandom.random_number(bytes.bytesize)

    # change it by a random offset that won't loop back around to its
    # original value
    offset = SecureRandom.random_number(254) + 1
    ord    = bytes[index].ord
    byte   = (ord + offset).modulo(256).chr

    # reconstruct the bytes with the twiddled bit inserted in place
    bytes[0, index] << byte << bytes[index.succ..-1]
  end

  def openssl_encrypt(key, nonce, aad, plaintext)
    cipher     = OpenSSL::Cipher.new(self.algo).encrypt
    cipher.key = key
    cipher.iv  = nonce
    cipher.aad = aad if aad

    cipher.update(plaintext) + cipher.final + cipher.gcm_tag
  end

  def openssl_decrypt(key, nonce, aad, ciphertext)
    tag        = ciphertext[ -16 ..  -1 ]
    ciphertext = ciphertext[   0 .. -17 ]

    cipher         = OpenSSL::Cipher.new(self.algo).decrypt
    cipher.key     = key
    cipher.iv      = nonce
    cipher.gcm_tag = tag
    cipher.aad     = aad if aad

    cipher.update(ciphertext).tap { cipher.verify }
  end
end if OpenSSL::Cipher.ciphers.include?('aes-256-gcm')
