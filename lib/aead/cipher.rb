require 'aead'

require 'openssl'
require 'openssl/cipher/aead'

#
# Wraps AEAD ciphers in a simplified interface.
#
class AEAD::Cipher
  autoload :AES_256_GCM,              'aead/cipher/aes_256_gcm'
  autoload :AES_256_CTR_HMAC_SHA_256, 'aead/cipher/aes_256_ctr_hmac_sha_256'

  def self.new(algorithm)
    # run normal Class#new if we're being called from a subclass
    return super unless self == AEAD::Cipher

    self.const_get algorithm.tr('-', '_').upcase
  end

  def self.generate_key
    SecureRandom.random_bytes(self.key_len)
  end

  def self.generate_nonce
    AEAD::Nonce.generate
  end

  def self.signature_compare(left, right)
    # short-circuit if the lengths are inequal
    return false if left.bytesize != right.bytesize

    # Constant-time string comparison algorithm:
    #   1. Break both strings into bytes
    #   2. XOR the strings together, byte by byte
    #      (any non-equal bytes will XOR to a nonzero value)
    #   3. OR the XOR'd bytes together
    #   4. If the result is nonzero, the strings differed.
    left   = left.bytes.to_a
    right  = right.bytes.to_a
    result = 0

    left.length.times do |i|
      result |= left[i] ^ right[i]
    end

    result == 0
  end

  def initialize(algorithm, key)
    _verify_key_bytesize(key, self.key_len)

    self.algorithm = algorithm
    self.key       = key
  end

  def key_len
    self.class.key_len
  end

  def iv_len
    self.class.iv_len
  end

  def tag_len
    self.class.tag_len
  end

  def nonce_len
    self.class.nonce_len
  end

  def encrypt(nonce, plaintext, aad = nil)
    _verify_nonce_bytesize(nonce, self.nonce_len)

    self._encrypt(
       _pad_nonce(nonce),
       plaintext,
       aad
    )
  end

  def decrypt(nonce, ciphertext, aad = nil)
    _verify_nonce_bytesize(nonce, self.nonce_len)

    self._decrypt(
      _pad_nonce(nonce),
      _extract_ciphertext(ciphertext, self.tag_len),
      aad,
      _extract_tag(ciphertext, self.tag_len)
    )
  end

  protected

  attr_accessor :algorithm
  attr_accessor :key

  def cipher(direction)
    yield OpenSSL::Cipher.new(algorithm).send(direction)
  end

  private

  def _verify_key_bytesize(key, key_len)
    raise ArgumentError, "key must be at least #{key_len} bytes" unless
      key.bytesize >= key_len
  end

  def _verify_nonce_bytesize(nonce, nonce_len)
    raise ArgumentError, "nonce must be at least #{nonce_len} bytes" unless
      nonce.bytesize >= nonce_len
  end

  def _pad_nonce(nonce)
    nonce.rjust(self.iv_len, "\0")
  end

  def _extract_ciphertext(ciphertext, tag_len)
    ciphertext[ 0 .. -tag_len - 1 ].to_s
  end

  def _extract_tag(ciphertext, tag_len)
    ciphertext[ -tag_len .. -1 ].to_s
  end
end
