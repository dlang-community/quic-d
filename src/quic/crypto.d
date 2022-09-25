module quic.crypto;

import deimos.openssl.kdf;
import deimos.openssl.evp;
import deimos.openssl.err;
import core.stdc.stdio : stderr;

int hkdf_extract(ubyte[] salt, ubyte[] key, ubyte[] initialSecret,
                    ulong expectedSecretLen, const(EVP_MD)* md = EVP_sha256)
out (result) {
    if (result < 1)
        ERR_print_errors_fp(stderr);
} do {
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, null);

    if (EVP_PKEY_derive_init(ctx) < 1)
        return -1;
    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_KDF_HKDF_MODE_EXTRACT_ONLY) < 1)
        return -1;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) < 1)
        return -1;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.ptr, cast(int) salt.length) < 1)
        return -1;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key.ptr, cast(int) key.length) < 1)
        return -1;

    ulong bufLenParam = expectedSecretLen;

    if (EVP_PKEY_derive(ctx, initialSecret.ptr, &bufLenParam) < 1)
        return -1;
    return 1;
}

unittest
{
    import std.conv : hexString;
    import std.digest : toHexString, LetterCase;
    ubyte[32] initial_secret;

    //Numerical values taken from the RFC 9001 Appendix A example 
    auto salt = cast(ubyte[]) hexString!"38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    auto key = cast(ubyte[]) hexString!"8394c8f03e515708";

    hkdf_extract(salt, key, initial_secret, 32);
    assert(initial_secret.toHexString!(LetterCase.lower) ==
    "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
}

int hkdf_expand(ubyte[] buffer, ubyte[] secret, ubyte[] label, ushort buffLen,
                                                const(EVP_MD)* md = EVP_sha256)
out (result) {
    if (result < 1)
        ERR_print_errors_fp(stderr);
} do {
    EVP_PKEY_CTX* ctx;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, null);

    if (EVP_PKEY_derive_init(ctx) < 1)
        return -1;
    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_KDF_HKDF_MODE_EXPAND_ONLY) < 1)
        return -1;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) < 1)
        return -1;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.ptr, cast(int) secret.length)
                                                                        < 1)
        return -1;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, label.ptr, cast(int) label.length) < 1)
        return -1;

    auto bufLenParam = cast(ulong) buffLen;
    if (EVP_PKEY_derive(ctx, buffer.ptr, &bufLenParam) < 1)
        return -1;
    return 1;
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

void hkdf_expand_label(ubyte[] buffer, ubyte[] secret, ubyte[] label,
                            ushort bufLen, const(EVP_MD)* md = EVP_sha256)
in {
    assert(label.length <= 250); //256 - tlsLabel.length
} do {
    ubyte[] HkdfLabel;
    ubyte[] tlsLabel = cast(ubyte[]) "tls13 "; 
    HkdfLabel ~= cast(ubyte) bufLen >> 8;
    HkdfLabel ~= cast(ubyte) bufLen & 0xff;
    HkdfLabel ~= cast(ubyte) (tlsLabel.length + label.length);
    HkdfLabel ~= tlsLabel;
    HkdfLabel ~= label;
    HkdfLabel ~= '\0';
    hkdf_expand(buffer, secret, HkdfLabel, bufLen, md);
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
    hkdf_expand_label(buf, initial_secret, client_in_label, cast(ushort) 32, EVP_sha256);
    assert(buf.toHexString!(LetterCase.lower) == "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
}

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
ubyte[] encrypt_packet(ubyte[] plaintext, ubyte[] aad, ubyte[] key,
                        ubyte[] iv, ubyte[] ciphertext, EVP_CIPHER_CTX* ctx,
                        const(EVP_CIPHER)* aead = EVP_aes_256_gcm)
out (result) {
    if (result == null)
        ERR_print_errors_fp(stderr);
} do {
    int len, ciphertext_len;
    //support for other AEAD ciphers to be added later
    if (EVP_EncryptInit_ex(ctx, aead, null, null, null) < 1)
        return null;
    if (EVP_EncryptInit_ex(ctx, null, null, key.ptr, iv.ptr) < 1)     
        return null;
    if (EVP_EncryptUpdate(ctx, null, &len, aad.ptr, cast(int) aad.length) < 1)
        return null;
    if (EVP_EncryptUpdate(ctx, ciphertext.ptr, &len, plaintext.ptr,
                                            cast(int) plaintext.length) < 1)
        return null;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext[len..$].ptr, &len) != 1)
        return null;
    ciphertext_len += len;

    return ciphertext[0..ciphertext_len];
}

ubyte[] decrypt_packet(ubyte[] ciphertext, ubyte[] aad, ubyte[] key,
                    ubyte[] iv, ubyte[] plaintext, EVP_CIPHER_CTX* cctx,
                    const(EVP_CIPHER)* aead = EVP_aes_256_gcm)
out (result) {
    if (result == null)
        ERR_print_errors_fp(stderr);
} do {
    int len, plaintext_len, ret;
    auto ctx = EVP_CIPHER_CTX_new();
    //support for other AEAD ciphers to be added later
    if (EVP_DecryptInit_ex(ctx, aead, null, null, null) < 1)
        return null;
    if (EVP_DecryptInit_ex(ctx, null, null, key.ptr, iv.ptr) < 1)     
        return null;
    if (EVP_DecryptUpdate(ctx, null, &len, aad.ptr, cast(int) aad.length) < 1)
        return null;
    if (EVP_DecryptUpdate(ctx, plaintext.ptr, &len, ciphertext.ptr,
                                            cast(int) ciphertext.length) < 1)
        return null;
    plaintext_len = len;
    ret = EVP_DecryptFinal_ex(ctx, plaintext[len..$].ptr, &len);
    if(ret > 0)
    {
        plaintext_len += len;
        return plaintext[0..plaintext_len];
    }
    else
        return null;
}
