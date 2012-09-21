require 'aead/cipher'
require 'aead/cipher/aes_hmac'

#
# Encrypt plaintext using the CTR mode of AES and authenticate the
# result with HMAC-SHA-256.
#
class AEAD::Cipher::AES_256_CTR_HMAC_SHA_256 < AEAD::Cipher
  include AEAD::Cipher::AES_HMAC

  def self.key_len;   64; end
  def self.iv_len;    16; end
  def self.nonce_len; 12; end
  def self.tag_len;   32; end

  def self.encryption_key_len; 32; end
  def self.signing_key_len;    32; end

  def self.cipher_mode; 'aes-256-ctr'; end
  def self.digest_mode; 'SHA256'; end
end
