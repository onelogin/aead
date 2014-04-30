# aead #

Ruby library for generating AEAD (authenticated encryption with
associated data) ciphertexts.

## Description ##

Modern encryption best practices encourage the use of authenticated
encryption: ciphertext contents should be authenticated during the
decryption process, preventing either malicious or unintentional
silent corruption.

This library provides an extension to the Ruby OpenSSL bindings that
allows access to the GCM mode supported by OpenSSL (in versions higher
than 1.0.0). For Rubies linked against older versions of OpenSSL, a
mode is provided to perform AES-256-CTR with HMAC-SHA-256, as
[encouraged by Colin Percival](http://www.daemonology.net/blog/2009-06-11-cryptographic-right-answers.html).

## Getting Started ##

```ruby
require 'aead'

# currently, AES-256-GCM and AES-256-CTR-HMAC-SHA-256 are supported
mode   = AEAD::Cipher.new('AES-256-GCM')
key    = mode.generate_key
nonce  = mode.generate_nonce

cipher    = mode.new(key)
aead      = cipher.encrypt(nonce, 'authentication data', 'plaintext')
plaintext = cipher.decrypt(nonce, 'authentication data', aead)
```

If any of the key, nonce, authentication data, or ciphertext has been
altered, the ciphertext will fail to decrypt and an exception will be
raised.

```ruby
cipher.decrypt(nonce, 'authentication data', aead.succ) # => ArgumentError
```

## Security Guidelines ##

Nonces should *never* be used to encrypt more than one plaintext with
the same key.

Nonces generated through the API provided by this gem are guaranteed
to be unique as long as the state file is not corrupted or
removed. The state file is located in `/var/tmp/ruby-aead`. 

Nonce generation is thread-safe and tolerates being performed
simultaneously in separate processes.

If you believe you have discovered a security vulnerability in this
gem, please email `security@onelogin.com` with a description. We
follow responsible disclosure guidelines, and will work with you to
quickly find a resolution.
