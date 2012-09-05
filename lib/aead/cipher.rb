require 'aead'

require 'openssl'
require 'openssl/cipher/aead'

#
# Wraps AEAD ciphers in a simplified interface.
#
class AEAD::Cipher
  # Recommended nonce length per RFC 5116
  #   http://tools.ietf.org/pdf/rfc5116.pdf
  NONCE_BYTES = 12

  def initialize(algorithm, key, nonce, aad = nil)
    self.cipher = OpenSSL::Cipher.new(algorithm)
    self.key    = key
    self.nonce  = nonce.rjust(self.cipher.iv_len, "\0")
    self.aad    = aad

    raise ArgumentError, "key must be #{cipher.key_len} bytes" unless
      key.bytesize == cipher.key_len

    raise ArgumentError, "nonce must be no fewer than 12 bytes" unless
      nonce.bytesize >= NONCE_BYTES
  end

  def encrypt(&block)
    self.perform!(:encrypt, nil, &block)
  end

  def decrypt(tag = nil, &block)
    self.perform!(:decrypt, tag, &block)
  end

  protected

  attr_accessor :cipher
  attr_accessor :key
  attr_accessor :nonce
  attr_accessor :aad

  def perform!(direction, tag)
    self.cipher.send(direction)

    self.cipher.key      = self.key
    self.cipher.iv       = self.nonce
    self.cipher.gcm_tag  = tag if tag
    self.cipher.aad      = self.aad if self.aad

    yield self.cipher
  ensure
    self.reset!
  end

  def reset!
    self.cipher.reset
  end
end
