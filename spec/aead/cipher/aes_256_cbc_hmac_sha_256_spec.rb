require 'spec_helper'
require 'aead/cipher/aes_256_ctr_hmac_sha_256'

describe AEAD::Cipher::AES_256_CBC_HMAC_SHA_256 do
  subject { self.cipher.new(self.key) }

  let(:algo)      { 'aes-256-cbc-hmac-sha-256' }
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

  it 'must require a 512-bit or larger key' do
    bad_keys  = [  0,  1, 33, 63 ].map {|size| SecureRandom.random_bytes(size) }
    good_keys = [ 64, 65, 10_000 ].map {|size| SecureRandom.random_bytes(size) }

    bad_keys.each do |key|
      -> { self.cipher.new(key) }.must_raise ArgumentError
    end

    good_keys.each do |key|
      self.cipher.new(key).must_be_kind_of AEAD::Cipher
    end
  end

  it 'must require a 12-byte or larger nonce' do
    bad_nonces  = [0,   1,  11 ].map {|size| SecureRandom.random_bytes(size) }
    good_nonces = [12, 13, 256 ].map {|size| SecureRandom.random_bytes(size) }

    bad_nonces.each do |nonce|
      -> { self.subject.encrypt(nonce, self.plaintext, self.aad) }.
        must_raise ArgumentError
    end

    good_nonces.each do |nonce|
      self.subject.encrypt(nonce, self.plaintext, self.aad).
        must_be_kind_of String
    end
  end

  it 'must require a non-empty plaintext' do
    -> { self.subject.encrypt(nonce, self.aad, nil) }.must_raise ArgumentError
    -> { self.subject.encrypt(nonce, self.aad,  '') }.must_raise ArgumentError
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

  it 'must resist manipulation of the signing key' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    cipher     = self.cipher.new key[0, 32] << twiddle(key[32, 32])

    -> { cipher.decrypt(self.nonce, self.aad, ciphertext) }.
      must_raise ArgumentError
  end

  it 'must resist manipulation of the nonce' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    nonce      = twiddle(self.nonce)

    -> { self.subject.decrypt(nonce, self.aad, ciphertext) }.
      must_raise ArgumentError
  end

  it 'must resist manipulation of the ciphertext' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    ciphertext = twiddle(ciphertext)

    -> { self.subject.decrypt(self.nonce, self.aad, ciphertext) }.
      must_raise ArgumentError
  end

  it 'must resist manipulation of the aad' do
    ciphertext = subject.encrypt(self.nonce, self.aad, self.plaintext)
    aad        = twiddle(self.aad)

    -> { self.subject.decrypt(self.nonce, aad, ciphertext) }.
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
    encryption_key = key[ 0, 32]
    signing_key    = key[32, 32]
    cipher         = OpenSSL::Cipher.new('aes-256-cbc').encrypt
    nonce          = nonce.rjust(16, "\0")
    cipher.key     = encryption_key
    cipher.iv      = nonce

    ciphertext = cipher.update(plaintext) + cipher.final
    tag        = OpenSSL::HMAC.digest 'SHA256', signing_key,
      [ 'aes-256-cbc' .length ].pack('Q>') << 'aes-256-cbc'  <<
      [ encryption_key.length ].pack('Q>') << encryption_key <<
      [ ciphertext    .length ].pack('Q>') << ciphertext     <<
      [ nonce         .length ].pack('Q>') << nonce          <<
      [ aad           .length ].pack('Q>') << aad

    ciphertext + tag
  end

  def openssl_decrypt(key, nonce, aad, ciphertext)
    encryption_key = key[ 0, 32]
    signing_key    = key[32, 32]
    tag        = ciphertext[ -32 ..  -1 ]
    ciphertext = ciphertext[   0 .. -33 ]

    cipher         = OpenSSL::Cipher.new('aes-256-cbc').decrypt
    cipher.key     = encryption_key
    cipher.iv      = nonce.rjust(16, "\0")

    cipher.update(ciphertext) + cipher.final
  end
end
