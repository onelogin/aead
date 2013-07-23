require 'aead/cipher'

#
# Provides the implementation details of AES + GCM, assuming the
# class including this module has defined proper class methods.
#
module AEAD::Cipher::AES_GCM

  #def self.included(base)
  #  base.extend(ClassMethods)
  #end

  #
  # Instantiates the cipher with a secret key.
  #
  # @param [String] key a secret encryption key
  #
  def initialize(key, options = {})
    super(self.class.cipher_mode, key, options)
  end

  def nonce_len
    iv_len
  end

  #module ClassMethods
  #  def iv_len
  #    @iv_len || 12
  #  end
  #  def nonce_len; iv_len; end
  #
  #  def iv_len=(value)
  #    @iv_len = value
  #  end
  #end

  protected

  def _encrypt(nonce, aad, plaintext)
    self.cipher(:encrypt) do |cipher|
      cipher.gcm_iv_len = self.iv_len
      cipher.key        = self.key
      cipher.iv         = nonce
      cipher.aad        = aad.to_s if aad

      ciphertext = cipher.update(plaintext) unless plaintext.nil? || plaintext.empty?
      ciphertext = (ciphertext || "") + cipher.final + cipher.gcm_tag
    end
  end

  def _decrypt(nonce, aad, ciphertext, tag)
    self.cipher(:decrypt) do |cipher|
      cipher.gcm_iv_len = self.iv_len
      cipher.key        = self.key
      cipher.iv         = nonce
      cipher.gcm_tag    = tag
      cipher.aad        = aad.to_s if aad

      cipher.update(ciphertext).tap { cipher.verify }
    end
  rescue OpenSSL::Cipher::CipherError
    raise ArgumentError, 'ciphertext failed authentication step'
  end
end
