require 'mkmf'

dir_config('openssl')
have_header("openssl/ssl.h")
have_library("ssl", "SSLv23_method")

create_makefile('openssl/cipher/aead')
