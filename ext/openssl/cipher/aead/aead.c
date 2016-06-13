#include <ruby.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

VALUE dOSSL;
VALUE eCipherError;

#define GetCipherInit(obj, ctx) do { \
    TypedData_Get_Struct((obj), EVP_CIPHER_CTX, RTYPEDDATA_TYPE(obj), (ctx)); \
} while (0)
#define GetCipher(obj, ctx) do { \
    GetCipherInit((obj), (ctx)); \
    if (!(ctx)) { \
	ossl_raise(rb_eRuntimeError, "Cipher not inititalized!"); \
    } \
} while (0)

static VALUE
ossl_make_error(VALUE exc, const char *fmt, va_list args)
{
    char buf[BUFSIZ];
    const char *msg;
    long e;
    int len = 0;

#ifdef HAVE_ERR_PEEK_LAST_ERROR
    e = ERR_peek_last_error();
#else
    e = ERR_peek_error();
#endif
    if (fmt) {
        len = vsnprintf(buf, BUFSIZ, fmt, args);
    }
    if (len < BUFSIZ && e) {
        if (dOSSL == Qtrue) /* FULL INFO */
            msg = ERR_error_string(e, NULL);
        else
            msg = ERR_reason_error_string(e);
        len += snprintf(buf+len, BUFSIZ-len, "%s%s", (len ? ": " : ""), msg);
    }
    if (dOSSL == Qtrue){ /* show all errors on the stack */
        while ((e = ERR_get_error()) != 0){
            rb_warn("error on stack: %s", ERR_error_string(e, NULL));
        }
    }
    ERR_clear_error();

    if(len > BUFSIZ) len = rb_long2int(strlen(buf));
    return rb_exc_new(exc, buf, len);
}

void
ossl_raise(VALUE exc, const char *fmt, ...)
{
    va_list args;
    VALUE err;
    va_start(args, fmt);
    err = ossl_make_error(exc, fmt, args);
    va_end(args);
    rb_exc_raise(err);
}

static VALUE
ossl_cipher_set_aad(VALUE self, VALUE data)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char  *in      = NULL;
    int             in_len  = 0;
    int             out_len = 0;

    StringValue(data);

    in     = (unsigned char *) RSTRING_PTR(data);
    in_len = RSTRING_LEN(data);

    GetCipher(self, ctx);

    if (!EVP_CipherUpdate(ctx, NULL, &out_len, in, in_len))
        ossl_raise(eCipherError, NULL);

    return self;
}

static VALUE
ossl_cipher_get_tag(VALUE self)
{
    EVP_CIPHER_CTX *ctx;
    VALUE           tag;

    tag = rb_str_new(NULL, 16);

    GetCipher(self, ctx);

#ifndef EVP_CTRL_GCM_GET_TAG
    ossl_raise(eCipherError, "your version of OpenSSL doesn't support GCM");
#else
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, (unsigned char *)RSTRING_PTR(tag)))
        ossl_raise(eCipherError, NULL);
#endif

    return tag;
}

static VALUE
ossl_cipher_set_tag(VALUE self, VALUE data)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char  *in     = NULL;
    int             in_len = 0;

    StringValue(data);

    in     = (unsigned char *) RSTRING_PTR(data);
    in_len = RSTRING_LEN(data);

    GetCipher(self, ctx);

#ifndef EVP_CTRL_GCM_SET_TAG
    ossl_raise(eCipherError, "your version of OpenSSL doesn't support GCM");
#else
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, in_len, in))
        ossl_raise(eCipherError, NULL);
#endif

    return data;
}

static VALUE
ossl_cipher_set_iv_length(VALUE self, VALUE iv_length)
{
    EVP_CIPHER_CTX *ctx;
    int             ivlen = NUM2INT(iv_length);
    GetCipher(self, ctx);

#ifndef EVP_CTRL_GCM_SET_IVLEN
    ossl_raise(eCipherError, "your version of OpenSSL doesn't support GCM");
#else
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
        ossl_raise(eCipherError, NULL);
#endif

    return iv_length;
}

static VALUE
ossl_cipher_verify(VALUE self)
{
    EVP_CIPHER_CTX *ctx;
    int             out_len = 0;

    GetCipher(self, ctx);

    if (!EVP_CipherUpdate(ctx, NULL, &out_len, NULL, 0))
        ossl_raise(eCipherError, "ciphertext failed authentication step");

    return rb_str_new(0, 0);
}

void
Init_aead(void)
{
    rb_require("openssl");
    VALUE cOSSLCipher = rb_path2class("OpenSSL::Cipher");
    eCipherError = rb_path2class("OpenSSL::Cipher::CipherError");

    rb_define_method(cOSSLCipher, "aad=",        ossl_cipher_set_aad,       1);
    rb_define_method(cOSSLCipher, "gcm_tag",     ossl_cipher_get_tag,       0);
    rb_define_method(cOSSLCipher, "gcm_tag=",    ossl_cipher_set_tag,       1);
    rb_define_method(cOSSLCipher, "gcm_iv_len=", ossl_cipher_set_iv_length, 1);
    rb_define_method(cOSSLCipher, "verify",      ossl_cipher_verify,        0);
}
