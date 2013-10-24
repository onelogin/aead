require 'aead'

require 'openssl'
require 'openssl/cipher/aead'
require 'securerandom'

#
# Wraps AEAD ciphers in a simplified interface.
#
class AEAD::Cipher
  autoload :AES_256_GCM,              'aead/cipher/aes_256_gcm'
  autoload :AES_256_CBC_HMAC_SHA_256, 'aead/cipher/aes_256_cbc_hmac_sha_256'
  autoload :AES_256_CTR_HMAC_SHA_256, 'aead/cipher/aes_256_ctr_hmac_sha_256'

  #
  # Returns a particular Cipher implementation.
  #
  # @param [String] algorithm the AEAD implementation to use
  # @return [Class] the cipher implementation
  #
  def self.new(algorithm)
    # run normal Class#new if we're being called from a subclass
    return super unless self == AEAD::Cipher

    # TODO: ciphers should register themselves, as opposed to using a
    # potentiall-unsafe const_get
    self.const_get algorithm.tr('-', '_').upcase
  end

  #
  # Returns a securely-generated key of appropriate length for the
  # current Cipher.
  #
  # @return [String] a random key
  #
  def self.generate_key
    SecureRandom.random_bytes(self.key_len)
  end

  #
  # Returns a unique nonce for the current Cipher.
  #
  # @return [String] a random key
  #
  def self.generate_nonce
    AEAD::Nonce.generate
  end

  #
  # Does a constant-time comparison between two strings. Useful to
  # avoid timing attacks when comparing a generated signature against
  # a user-provided signature.
  #
  # @param [String] left any string
  # @param [String] right any string
  # @return [Boolean] whether or not the strings are equal
  #
  def self.signature_compare(left, right)
    # short-circuit if the lengths are inequal
    return false if left.to_s.bytesize != right.bytesize

    # Constant-time string comparison algorithm:
    #   1. Break both strings into bytes
    #   2. Subtract the strings from one-another, byte by byte
    #      (any non-equal bytes will subtract to a nonzero value)
    #   3. OR the XOR'd bytes together
    #   4. If the result is nonzero, the strings differed.
    left   = left.bytes.to_a
    right  = right.bytes.to_a
    result = 0

    left.length.times do |i|
      result |= left[i] - right[i]
    end

    result == 0
  end

  #
  # The length of keys of encryption keys used by the current Cipher.
  #
  # @return [Integer] the length of keys in bytes
  #
  def key_len
    self.class.key_len
  end

  #
  # The length of nonces used by the current Cipher.
  #
  # @return [Integer] the length of nonces in bytes
  #
  def nonce_len
    self.class.nonce_len
  end

  #
  # Encrypts a plaintext using the current Cipher.
  #
  # IMPORTANT: Do not ever encrypt data using the same nonce more than
  # once given a particular secret key. Doing so will violate the
  # security guarantees of the AEAD cipher.
  #
  # @param [String] nonce a unique nonce, never before used with the
  #   current encryption key
  # @param [String, nil] aad arbitrary additional authentication data that
  #   must later be provided to decrypt the aead
  # @param [String] plaintext arbitrary plaintext
  # @return [String] the generated AEAD
  #
  def encrypt(nonce, aad, plaintext)
    if nonce.respond_to?(:force_encoding)
      nonce    .force_encoding('ASCII-8BIT')
      aad      .force_encoding('ASCII-8BIT')
      plaintext.force_encoding('ASCII-8BIT')
    end

    _verify_nonce_bytesize(nonce, self.nonce_len)
    _verify_plaintext_presence(plaintext)

    self._encrypt(
       _pad_nonce(nonce),
       aad,
       plaintext
    )
  end

  #
  # Decrypts a plaintext using the current Cipher.
  #
  # @param [String] nonce the nonce used when encrypting the AEAD
  # @param [String] aad the additional authentication data used when
  #   encrypting the AEAD
  # @param [String] aead the encrypted AEAD
  # @return [String] the original plaintext
  #
  def decrypt(nonce, aad, aead)
    if nonce.respond_to?(:force_encoding)
      nonce.force_encoding('ASCII-8BIT')
      aad  .force_encoding('ASCII-8BIT')
      aead .force_encoding('ASCII-8BIT')
    end

    _verify_nonce_bytesize(nonce, self.nonce_len)

    self._decrypt(
      _pad_nonce(nonce),
      aad,
      _extract_ciphertext(aead, self.tag_len),
      _extract_tag(aead, self.tag_len)
    )
  end

  protected

  # The OpenSSL algorithm to be used by the cipher.
  attr_accessor :algorithm

  # The secret key provided by the user.
  attr_accessor :key

  #
  # Initializes the cipher.
  #
  # @param [String] algorithm the full encryption mode to be used in
  #   calls to {#cipher}.
  # @param [String] key the encryption key supplied by the user
  # @return [Cipher] the initialized Cipher
  #
  def initialize(algorithm, key)
    _verify_key_bytesize(key, self.key_len)

    self.algorithm = algorithm.dup.freeze
    self.key       = key.dup.freeze

    self.freeze
  end


  #
  # Yields the {OpenSSL::Cipher} for the current {#algorithm}
  #
  def cipher(direction)
    yield OpenSSL::Cipher.new(algorithm).send(direction)
  end

  #
  # The length of initialization vectors used by the current Cipher.
  #
  # @return [Integer] the length of initialization vectors in bytes
  #
  def iv_len
    self.class.iv_len
  end

  #
  # The length of authentication tags generated by the current Cipher.
  #
  # @return [Integer] the length of authentication tags in bytes
  #
  def tag_len
    self.class.tag_len
  end

  private

  def _verify_key_bytesize(key, key_len)
    raise ArgumentError, 'no key provided' unless
      key

    raise ArgumentError, "key must be at least #{key_len} bytes" unless
      key.bytesize >= key_len
  end

  def _verify_nonce_bytesize(nonce, nonce_len)
    raise ArgumentError, "nonce must be at least #{nonce_len} bytes" unless
      nonce.bytesize == nonce_len
  end

  def _verify_plaintext_presence(plaintext)
    raise ArgumentError, 'plaintext must not be empty' unless
      not plaintext.nil? and not plaintext.empty?
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
