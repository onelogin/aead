require 'aead/cipher'

#
# Provides the implementation details of AES + HMAC, assuming the
# class including this module has defined proper class methods.
#
module AEAD::Cipher::AES_HMAC
  #
  # Initializes the cipher with a given secret encryption key.
  #
  # @param [String] key a secret encryption key
  #
  def initialize(key)
    super(self.class.cipher_mode, key)
  end

  protected

  def encryption_key
    self.key[0, self.class.encryption_key_len]
  end

  def signing_key
    self.key[self.class.encryption_key_len, self.class.signing_key_len]
  end

  def _encrypt(nonce, aad, plaintext)
    self.cipher(:encrypt) do |cipher|
      cipher.key = self.encryption_key
      cipher.iv  = nonce

      ciphertext = cipher.update(plaintext) + cipher.final
      mac        = hmac_generate(nonce, aad.to_s, ciphertext)

      ciphertext << mac
    end
  end

  def _decrypt(nonce, aad, ciphertext, tag)
    raise ArgumentError, 'ciphertext failed authentication step' unless
      hmac_verify(nonce, aad.to_s, ciphertext, tag)

    self.cipher(:decrypt) do |cipher|
      cipher.key = self.encryption_key
      cipher.iv  = nonce

      cipher.update(ciphertext) << cipher.final
    end
  end

  def hmac_generate(nonce, aad, ciphertext)
    OpenSSL::HMAC.digest self.class.digest_mode, self.signing_key,
      [ self.class.cipher_mode.length ].pack('Q>') << self.class.cipher_mode <<
      [ self.encryption_key   .length ].pack('Q>') << self.encryption_key    <<
      [ ciphertext            .length ].pack('Q>') << ciphertext             <<
      [ nonce                 .length ].pack('Q>') << nonce                  <<
      [ aad                   .length ].pack('Q>') << aad
  end

  def hmac_verify(nonce, aad, ciphertext, hmac)
    self.class.signature_compare(
      hmac_generate(nonce, aad, ciphertext),
      hmac
    )
  end
end
