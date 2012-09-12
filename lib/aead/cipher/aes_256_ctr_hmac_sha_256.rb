require 'aead/cipher'

class AEAD::Cipher::AES_256_CTR_HMAC_SHA_256 < AEAD::Cipher
  def self.key_len;   32; end
  def self.iv_len;    16; end
  def self.nonce_len; 12; end
  def self.tag_len;   32; end

  def initialize(key)
    super('aes-256-ctr', key)
  end

  protected

  def _encrypt(nonce, aad, plaintext)
    self.cipher(:encrypt) do |cipher|
      cipher.key = self.key
      cipher.iv  = nonce

      ciphertext = cipher.update(plaintext) + cipher.final
      mac        = hmac_generate(self.key, nonce, aad.to_s, ciphertext)

      ciphertext + mac
    end
  end

  def _decrypt(nonce, aad, ciphertext, tag)
    raise ArgumentError, 'ciphertext failed authentication step' unless
      hmac_verify(self.key, nonce, aad.to_s, ciphertext, tag)

    self.cipher(:decrypt) do |cipher|
      cipher.key = self.key
      cipher.iv  = nonce

      cipher.update(ciphertext) + cipher.final
    end
  end

  def hmac_generate(key, nonce, aad, ciphertext)
    OpenSSL::HMAC.digest 'SHA256', key,
      [ ciphertext.length ].pack('Q>') + ciphertext +
      [ nonce     .length ].pack('Q>') + nonce      +
      [ aad       .length ].pack('Q>') + aad
  end

  def hmac_verify(key, nonce, aad, ciphertext, hmac)
    self.class.signature_compare(
      hmac, hmac_generate(key, nonce, aad, ciphertext)
    )
  end
end
