#include <ruby.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Hack derived from ruby.h (State Commit 0534b970bc83814e77ea4bd8ba9b2d31fefc9b1e)
// to derive the EVP_CIPHTER_CTX pointer from the Ruby Openssl\Cipher class
// after the swap to TypedData_Get_Struct by the ruby builtin openssl extension
// that prevented just using Data_Get_Struct
#define Data_Get_Struct_Unsafe(obj,type,sval) \
    ((sval) = (type*)rb_data_object_get_unsafe(obj))

static inline void *
rb_data_object_get_unsafe(VALUE obj)
{
    //Check_Type(obj, RUBY_T_DATA);
    return ((struct RData *)obj)->data;
}
// --------------------------------------------------------------------------------

VALUE dOSSL;
VALUE eCipherError;

#define GetCipherInit(obj, ctx) do {                    \
        Data_Get_Struct_Unsafe((obj), EVP_CIPHER_CTX, (ctx));  \
    } while (0)

#define GetCipher(obj, ctx) do {                                        \
        GetCipherInit((obj), (ctx));                                    \
        if (!(ctx)) {                                                   \
            ossl_raise(rb_eRuntimeError, "Cipher not inititalized!");   \
        }                                                               \
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
    char           *in      = NULL;
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
    char           *in     = NULL;
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
    VALUE mOSSL       = rb_define_module("OpenSSL");
    VALUE mOSSLCipher = rb_define_class_under(mOSSL, "Cipher", rb_cObject);
    VALUE eOSSLError  = rb_define_class_under(mOSSL,"OpenSSLError",rb_eStandardError);

    eCipherError = rb_define_class_under(mOSSLCipher, "CipherError", eOSSLError);

    rb_define_method(mOSSLCipher, "aad=",        ossl_cipher_set_aad,       1);
    rb_define_method(mOSSLCipher, "gcm_tag",     ossl_cipher_get_tag,       0);
    rb_define_method(mOSSLCipher, "gcm_tag=",    ossl_cipher_set_tag,       1);
    rb_define_method(mOSSLCipher, "gcm_iv_len=", ossl_cipher_set_iv_length, 1);
    rb_define_method(mOSSLCipher, "verify",      ossl_cipher_verify,        0);
}
