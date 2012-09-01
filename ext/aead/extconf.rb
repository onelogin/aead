require 'mkmf'

have_header("openssl/ssl.h")
have_library("ssl", "SSLv23_method")

create_makefile('aead/ossl_aead')
