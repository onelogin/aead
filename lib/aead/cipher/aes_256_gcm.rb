require 'aead/cipher'

class AEAD::Cipher::AES_256_GCM < AEAD::Cipher
  def self.key_len;   32; end
  def self.iv_len;    12; end
  def self.nonce_len; 12; end
  def self.tag_len;   16; end

  def initialize(key)
    super('aes-256-gcm', key)
  end

  protected

  def _encrypt(nonce, plaintext, aad)
    self.cipher(:encrypt) do |cipher|
      cipher.key = self.key
      cipher.iv  = nonce
      cipher.aad = aad if aad

      cipher.update(plaintext) + cipher.final + cipher.gcm_tag
    end
  end

  def _decrypt(nonce, ciphertext, aad, tag)
    self.cipher(:decrypt) do |cipher|
      cipher.key     = self.key
      cipher.iv      = nonce
      cipher.gcm_tag = tag
      cipher.aad     = aad if aad

      cipher.update(ciphertext).tap { cipher.verify }
    end
  end
end
