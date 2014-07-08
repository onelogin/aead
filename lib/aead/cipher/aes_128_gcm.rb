require 'aead/cipher'
require 'aead/cipher/aes_gcm'

#
# Encrypt plaintext using the Galois Counter Mode of AES.
#
class AEAD::Cipher::AES_128_GCM < AEAD::Cipher
  include AEAD::Cipher::AES_GCM

  def self.cipher_mode; 'aes-128-gcm'; end

  def self.key_len;   16; end
  def self.iv_len;    12; end
  #def self.nonce_len; 12; end
  def self.tag_len;   16; end

end
