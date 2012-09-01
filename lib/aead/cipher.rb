require 'aead'

class AEAD::Cipher
  # Recommended nonce length per RFC 5116
  #   http://tools.ietf.org/pdf/rfc5116.pdf
  NONCE_BYTES = 12

  # TODO: AAD set to nil or empty string?
  # TODO: nil tag vs blank
  def initialize(algorithm, key, nonce, aad = nil, tag = nil)
    self.cipher = OpenSSL::Cipher.new(algorithm)
    self.key    = key
    self.nonce  = nonce
    self.aad    = aad
    self.tag    = tag

    raise ArgumentError, "key must be #{cipher.key_len} bytes" unless
      key.bytesize == cipher.key_len

    raise ArgumentError, "nonce must be no fewer than 12 bytes" unless
      nonce.bytesize >= NONCE_BYTES
  end

  def encrypt(&block)
    self.perform!(:encrypt, &block)
  end

  def decrypt(&block)
    self.perform!(:decrypt, &block)
  end

  protected

  attr_accessor :cipher
  attr_accessor :key
  attr_accessor :nonce
  attr_accessor :aad
  attr_accessor :tag

  def perform!(direction)
    case direction
      when :encrypt then self.cipher.encrypt
      when :decrypt then self.cipher.decrypt
      else raise ArgumentError, 'cipher must be used to encrypt or decrypt'
    end

    self.cipher.key = key
    self.cipher.iv  = nonce.rjust(self.cipher.iv_len, "\0")
    self.cipher.tag = tag if tag
    self.cipher.aad = aad if aad

    yield self.cipher.tap { self.reset! }
  end

  def reset!
    self.cipher.reset
    self.cipher = nil
  end
end
