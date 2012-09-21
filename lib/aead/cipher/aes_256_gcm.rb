require 'aead/cipher'

#
# Encrypt plaintext using the Galois Counter Mode of AES.
#
class AEAD::Cipher::AES_256_GCM < AEAD::Cipher
  def self.key_len;   32; end
  def self.iv_len;    12; end
  def self.nonce_len; 12; end
  def self.tag_len;   16; end

  #
  # Instantiates the cipher with a secret key.
  #
  # @param [String] key a secret encryption key
  #
  def initialize(key)
    super('aes-256-gcm', key)
  end

  protected

  def _encrypt(nonce, aad, plaintext)
    self.cipher(:encrypt) do |cipher|
      cipher.key = self.key
      cipher.iv  = nonce
      cipher.aad = aad.to_s if aad

      cipher.update(plaintext) + cipher.final + cipher.gcm_tag
    end
  end

  def _decrypt(nonce, aad, ciphertext, tag)
    self.cipher(:decrypt) do |cipher|
      cipher.key     = self.key
      cipher.iv      = nonce
      cipher.gcm_tag = tag
      cipher.aad     = aad.to_s if aad

      cipher.update(ciphertext).tap { cipher.verify }
    end
  rescue OpenSSL::Cipher::CipherError
    raise ArgumentError, 'ciphertext failed authentication step'
  end
end
