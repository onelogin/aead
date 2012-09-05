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

  def generate_key_256_bits
    _generate_key(256)
  end

  def generate_nonce
    _nonces.shift
  end

  def generate_nonces(count)
    _nonces.shift(count)
  end

  def aes_256_ctr_hmac_sha_256_encrypt(key, nonce, aad, plaintext)
    AEAD::Cipher.new('aes-256-ctr', key, nonce).encrypt do |cipher|
      ciphertext = cipher.update(plaintext) + cipher.final
      auth       = ciphertext + nonce + aad
      mac        = OpenSSL::HMAC.digest('SHA256', key, auth)

      ciphertext + mac
    end
  end

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

  def aes_256_gcm_encrypt(key, nonce, aad, plaintext)
    AEAD::Cipher.new('aes-256-gcm', key, nonce, aad).encrypt do |cipher|
      cipher.update(plaintext) + cipher.final + cipher.gcm_tag
    end
  end

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
