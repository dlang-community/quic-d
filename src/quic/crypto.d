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

void handleErrors()
{ 
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

    //Numerical values taken from the RFC 9001 Appendix A example 
    auto salt = cast(ubyte[]) hexString!"38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    auto key = cast(ubyte[]) hexString!"8394c8f03e515708";
    auto digest = cast(ubyte[]) "sha256";

    hkdf_extract(salt, key, digest, initial_secret);
    assert(initial_secret.toHexString!(LetterCase.lower) ==
    "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
}

void hkdf_expand(const(EVP_MD)* md, ubyte[] buffer, ubyte[] secret,
                                                ubyte[] label,ushort buffLen)
{
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, null);

    if (EVP_PKEY_derive_init(ctx) < 1)
        handleErrors;
    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_KDF_HKDF_MODE_EXPAND_ONLY) < 1)
        handleErrors;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) < 1)
        handleErrors;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.ptr, cast(int) secret.length)
                                                                        < 1)
        handleErrors;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, label.ptr, cast(int) label.length) < 1)
        handleErrors;

    auto bufLenParam = cast(ulong) buffLen;
    if (EVP_PKEY_derive(ctx, buffer.ptr, &bufLenParam) < 1)
        handleErrors;
}

/* RFC8446 7.1.  Key Schedule
 *     Where HkdfLabel is specified as:
 *
 *     struct {
 *         uint16 length = Length;
 *         opaque label<7..255> = "tls13 " + Label;
 *         opaque context<0..255> = Context;
 *     } HkdfLabel;
 */

void hkdf_expand_label(const(EVP_MD)* md, ubyte[] buffer, ubyte[] secret,
                                    ubyte[] label, ushort bufLen)
in {
    assert(label.length <= 250); //256 - tlsLabel.length
}
do {
    ubyte[] HkdfLabel;
    ubyte[] tlsLabel = cast(ubyte[]) "tls13 "; 
    HkdfLabel ~= cast(ubyte) bufLen >> 8;
    HkdfLabel ~= cast(ubyte) bufLen & 0xff;
    HkdfLabel ~= cast(ubyte) (tlsLabel.length + label.length);
    HkdfLabel ~= tlsLabel;
    HkdfLabel ~= label;
    HkdfLabel ~= '\0';
    hkdf_expand(md, buffer, secret, HkdfLabel, bufLen);
}

unittest
{
    import std.conv : hexString;
    import std.digest : toHexString, LetterCase;
    import deimos.openssl.evp;
    //Numerical values taken from the RFC 9001 Appendix A example 
    auto initial_secret = cast(ubyte[]) hexString!"7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44";
    auto client_in_label = cast(ubyte[]) "client in";
    
    ubyte[32] buf;
    hkdf_expand_label(EVP_sha256, buf, initial_secret, client_in_label, cast(ushort) 32);
    assert(buf.toHexString!(LetterCase.lower) == "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
}

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
int encrypt_packet(ubyte[] plaintext, ubyte[] aad, ubyte[] key,
                        ubyte[] iv, ubyte[] ciphertext, EVP_CIPHER_CTX* ctx,
                        const(EVP_CIPHER)* aead = EVP_aes_256_gcm)
{
    int len, ciphertext_len;
    //support for other AEAD ciphers to be added later
    if (EVP_EncryptInit_ex(ctx, aead, null, null, null) < 1)
        handleErrors;
    if (EVP_EncryptInit_ex(ctx, null, null, key.ptr, iv.ptr) < 1)
        handleErrors;
    if (EVP_EncryptInit_ex(ctx, null, null, key.ptr, iv.ptr) < 1)     
        handleErrors;
    if (EVP_EncryptUpdate(ctx, null, &len, aad.ptr, cast(int) aad.length) < 1)
        handleErrors;
    if (EVP_EncryptUpdate(ctx, ciphertext.ptr, &len, plaintext.ptr,
                                            cast(int) plaintext.length) < 1)
        handleErrors;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext[len..$].ptr, &len) != 1)
        handleErrors;

    return ciphertext_len;
}
