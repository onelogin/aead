require 'openssl'
require 'securerandom'

module AEAD
  autoload :Cipher, 'aead/cipher'
  autoload :Nonce,  'aead/nonce'

  # Length of a byte. Unlikely to change, but magic numbers are bad,
  # so this is moved out into a constant for clarity.
  BYTE_SIZE = 8

  module_function

  # def generate_key_128_bits
  #   _generate_key(128)
  # end

  # def generate_key_192_bits
  #   _generate_key(192)
  # end

  #
  # Generates a 256-bit key using a cryptographically secure PRNG.
  #
  # @return [String] 256-bit encryption key
  def generate_key_256_bits
    _generate_key(256)
  end

  #
  # Generates an RFC 5116 compliant nonce for use with AEAD encryption
  # modes.
  #
  # @return [String] 12-octet nonce
  #
  def generate_nonce
    _nonces.shift
  end

  #
  # Generates multiple RFC 5116 compliant nonces for use with AEAD
  # encryption modes.
  #
  # @param [Integer] count the number of nonces to generate
  # @return [Array<String>] an array of 12-octet nonces
  #
  def generate_nonces(count)
    _nonces.shift(count)
  end

  #
  # Encrypts a plaintext with AES-256-CTR and appends an HMAC
  # generated from the ciphertext and associated authentication
  # data.
  #
  # Note that no nonce should be reused with the same key to perform
  # encryption. Once a nonce length has been used with a key, all
  # future nonces used with that key *must* be of the same length.
  #
  # @param [String] key 256-bit encryption key
  # @param [String] nonce unique bit string never before used with `key`
  # @param [String] aad non-secret additional authentication data
  # @param [String] plaintext text to encrypt
  # @return [String] encrypted and authenticated ciphertext
  #
  def aes_256_ctr_hmac_sha_256_encrypt(key, nonce, aad, plaintext)
    AEAD::Cipher.new('aes-256-ctr', key, nonce).encrypt do |cipher|
      ciphertext = cipher.update(plaintext) + cipher.final
      auth       = ciphertext + nonce + aad
      mac        = OpenSSL::HMAC.digest('SHA256', key, auth)

      ciphertext + mac
    end
  end

  #
  # Decrypts a ciphertext with AES-256-CTR after verifying the HMAC
  # against the ciphertext and associated authentication data. If any
  # of the key, nonce, aad, or ciphertext has been changed, raises an
  # exception with exceedingly high probability.
  #
  # @param [String] key 256-bit encryption key used to encrypt ciphertext
  # @param [String] nonce nonce used to encrypt ciphertext
  # @param [String] aad non-secret additional authentication data
  # @param [String] ciphertext ciphertext to decrypt
  # @return [String] decrypted and authenticated plaintext
  #
  def aes_256_ctr_hmac_sha_256_decrypt(key, nonce, aad, ciphertext)
    mac        = ciphertext[ -32 ..  -1 ].to_s
    ciphertext = ciphertext[   0 .. -33 ].to_s
    auth       = ciphertext + nonce + aad

    raise ArgumentError, 'ciphertext could not be authenticated' unless
      self.constant_time_equals?(mac, OpenSSL::HMAC.digest('SHA256', key, auth))

    AEAD::Cipher.new('aes-256-ctr', key, nonce).decrypt do |cipher|
      cipher.update(ciphertext) + cipher.final
    end
  end

  #
  # Encrypts a plaintext with AES-256-GCM, which returns an
  # authenticated ciphertext.
  #
  # Note that no nonce should be reused with the same key to perform
  # encryption. Once a nonce length has been used with a key, all
  # future nonces used with that key *must* be of the same length.
  #
  # @param [String] key 256-bit encryption key
  # @param [String] nonce unique bit string never before used with `key`
  # @param [String] aad non-secret additional authentication data
  # @param [String] plaintext text to encrypt
  # @return [String] encrypted and authenticated ciphertext
  #
  def aes_256_gcm_encrypt(key, nonce, aad, plaintext)
    AEAD::Cipher.new('aes-256-gcm', key, nonce, aad).encrypt do |cipher|
      cipher.update(plaintext) + cipher.final + cipher.gcm_tag
    end
  end

  #
  # Decrypts a ciphertext with AES-256-GCM, verifying the ciphertext
  # and associated authentication data against the tag produced during
  # encryption. If any of the key, nonce, aad, or ciphertext has been
  # changed, raises an exception with exceedingly high probability.
  #
  # @param [String] key 256-bit encryption key used to encrypt ciphertext
  # @param [String] nonce nonce used to encrypt ciphertext
  # @param [String] aad non-secret additional authentication data
  # @param [String] ciphertext ciphertext to decrypt
  # @return [String] decrypted and authenticated plaintext
  #
  def aes_256_gcm_decrypt(key, nonce, aad, ciphertext)
    tag        = ciphertext[ -16 ..  -1 ].to_s
    ciphertext = ciphertext[   0 .. -17 ].to_s

    AEAD::Cipher.new('aes-256-gcm', key, nonce, aad).decrypt(tag) do |cipher|
      cipher.update(ciphertext).tap { cipher.verify }
    end
  end

  # Constant-time string comparison algorithm:
  #   1. Break both strings into bytes
  #   2. XOR the strings together, byte by byte
  #      (any non-equal bytes will XOR to a nonzero value)
  #   3. OR the XOR'd bytes together
  #   4. If the result is nonzero, the strings differed.
  def constant_time_equals?(left, right)
    # short-circuit if the lengths are inequal
    return false if left.bytesize != right.bytesize

    # interleave the two strings' bytes
    byte_pairs = left.bytes.zip(right.bytes)

    # XOR each pair of bytes together
    xors = byte_pairs.map {|(l, r)| l ^ r }

    # OR all the results together to see if any bytes were different
    0 == xors.inject {|result, xor| result | xor }
  end

  private_class_method

  def _generate_key(bits)
    SecureRandom.random_bytes(bits / BYTE_SIZE)
  end

  def _nonces
    @nonces ||= AEAD::Nonce.new
  end
end
