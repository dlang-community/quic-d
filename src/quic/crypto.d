module quic.crypto;

import deimos.openssl.kdf;
import deimos.openssl.evp;
import deimos.openssl.err;
import core.stdc.stdio : stderr;

struct ossl_param
{
    const(char)* key;             /* the name of the parameter */
    ubyte data_type;     /* declare what kind of content is in data */
    void* data;                  /* value being passed in or out */
    size_t data_size;            /* data size */
    size_t return_size;          /* returned size */
}

enum OSSL_PARAM_UTF8_STRING = 4;
enum OSSL_PARAM_OCTET_STRING = 5;

void handleErrors() {                                                        
    ERR_print_errors_fp(stderr);                                                   
    assert(false);
}

void hkdf_extract(ubyte[] salt, ubyte[] key, ubyte[] digest, ubyte[] initial_secret)
{
    auto modeStr = "EXTRACT_ONLY".dup ~ '\0';
    ossl_param[] parameters;

    parameters ~= ossl_param("salt", OSSL_PARAM_OCTET_STRING, salt.ptr,
                            salt.length, 0);
    parameters ~= ossl_param("key", OSSL_PARAM_OCTET_STRING, key.ptr,
                            key.length, 0);
    parameters ~= ossl_param("digest", OSSL_PARAM_UTF8_STRING, digest.ptr,
                            digest.length, 0);
    parameters ~= ossl_param("mode", OSSL_PARAM_UTF8_STRING,
                            modeStr.ptr, 12, 0);
    parameters ~= ossl_param(null, 0, null, 0, 0);

    OSSL_PARAM* p = cast(OSSL_PARAM*) parameters.ptr;

    EVP_KDF *kdf;
    kdf = EVP_KDF_fetch(null, "hkdf", null);
    EVP_KDF_CTX *kctx;
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (EVP_KDF_CTX_set_params(kctx, p) < 1)
        handleErrors;
    if (EVP_KDF_derive(kctx, initial_secret.ptr, 32, p) < 1)
        handleErrors;
}

unittest
{
    import std.conv : hexString;
    import std.digest : toHexString, LetterCase;
    ubyte[32] initial_secret;

    //Numerical values taken from thee RFC 9001 Appendix A example 
    auto salt = cast(ubyte[]) hexString!"38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    auto key = cast(ubyte[]) hexString!"8394c8f03e515708";
    auto digest = cast(ubyte[]) "sha256";

    hkdf_extract(salt, key, digest, initial_secret);
    assert(initial_secret.toHexString!(LetterCase.lower) ==
    "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
}
