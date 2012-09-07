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

  private_class_method

  def _generate_key(bits)
    SecureRandom.random_bytes(bits / BYTE_SIZE)
  end
end
