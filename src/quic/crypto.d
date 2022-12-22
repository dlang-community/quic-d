module quic.crypto;

import deimos.openssl.evp : EVP_aes_256_gcm, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MD,
                            EVP_sha256, EVP_aes_128_ecb;
import deimos.openssl.err : ERR_print_errors_fp;
import core.stdc.stdio : stderr;

int hkdf_extract(ubyte[] salt, ubyte[] key, ubyte[] initialSecret,
                    ulong expectedSecretLen, const(EVP_MD)* md = EVP_sha256)
out (result) {
    if (result < 1)
        ERR_print_errors_fp(stderr);
} do {
    import deimos.openssl.evp : EVP_PKEY_CTX, EVP_PKEY_CTX_new_id,
                                EVP_PKEY_derive, EVP_PKEY_derive_init,
                                EVP_PKEY_HKDF;
                                

    import deimos.openssl.kdf : EVP_PKEY_CTX_hkdf_mode,
                                EVP_PKEY_CTX_set_hkdf_md,
                                EVP_PKEY_CTX_set1_hkdf_salt,
                                EVP_PKEY_CTX_set1_hkdf_key,
                                EVP_KDF_HKDF_MODE_EXTRACT_ONLY;

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
    import deimos.openssl.evp : EVP_PKEY_CTX,
                                EVP_PKEY_derive, EVP_PKEY_derive_init,
                                EVP_PKEY_HKDF, EVP_PKEY_CTX_new_id;

    import deimos.openssl.kdf : EVP_PKEY_CTX_add1_hkdf_info,
                                EVP_PKEY_CTX_hkdf_mode,
                                EVP_PKEY_CTX_set_hkdf_md,
                                EVP_PKEY_CTX_set1_hkdf_salt,
                                EVP_PKEY_CTX_set1_hkdf_key,
                                EVP_KDF_HKDF_MODE_EXPAND_ONLY;
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
ubyte[] aeadEncrypt(ubyte[] plaintext, ubyte[] aad, ubyte[] key,
                        ubyte[] iv, ubyte[] ciphertext, EVP_CIPHER_CTX* ctx,
                        const(EVP_CIPHER)* aead = EVP_aes_256_gcm)
out (result) {
    if (result == null)
        ERR_print_errors_fp(stderr);
} do {
    import deimos.openssl.evp : EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
                                EVP_EncryptUpdate;
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

ubyte[] aeadDecrypt(ubyte[] ciphertext, ubyte[] aad, ubyte[] key,
                    ubyte[] iv, ubyte[] plaintext, EVP_CIPHER_CTX* ctx,
                    const(EVP_CIPHER)* aead = EVP_aes_256_gcm)
out (result) {
    if (result == null)
        ERR_print_errors_fp(stderr);
} do {
    import deimos.openssl.evp : EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
                                EVP_DecryptUpdate;

    int len, plaintext_len;
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

    if (EVP_DecryptFinal_ex(ctx, plaintext[len..$].ptr, &len) >= 0)
        plaintext_len += len;
    else
        return null;

        return plaintext[0..plaintext_len];
}

unittest
{
    auto message = cast(ubyte[]) "some secret message";
    auto key = cast(ubyte[]) "a key";
    auto iv = cast(ubyte[]) "someIVsomeIV";
    auto aad = cast(ubyte[]) "additional data";
    ubyte[64] cipherBuffer;
    ubyte[64] decryptedBuffer;
    
    import deimos.openssl.evp : EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free; 
    auto ctx = EVP_CIPHER_CTX_new;
    auto encryptedMessage = aeadEncrypt(message, aad, key, iv, cipherBuffer,
                                                                        ctx);
    auto decryptedMessage = aeadDecrypt(encryptedMessage, aad, key, iv,
                                            decryptedBuffer, ctx);
    assert(message == decryptedMessage);
    EVP_CIPHER_CTX_free(ctx);
}

ubyte[] ecbEncrypt(ubyte[] plaintext, ubyte[] ciphertext,
                    ubyte[] key, EVP_CIPHER_CTX* ctx,
                    const(EVP_CIPHER)* aes = EVP_aes_128_ecb)
out (result) {
    if (result == null)
        ERR_print_errors_fp(stderr);
} do {
    import deimos.openssl.evp : EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal_ex;
    int len, ciphertext_len;
    if (EVP_EncryptInit_ex(ctx, aes, null, key.ptr, null) < 1)
        return null;
    if (EVP_EncryptUpdate(ctx, ciphertext.ptr, &len, plaintext.ptr,
                                            cast(int) plaintext.length) < 1)
        return null;
    if (EVP_EncryptFinal_ex(ctx, ciphertext[len..$].ptr, &len) != 1)
        return null;
    ciphertext_len += len;

    return ciphertext[0..ciphertext_len];
}

unittest
{
    import deimos.openssl.evp : EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free; 
    import std.conv : hexString;
    import std.digest : toHexString, LetterCase;

    auto ctx = EVP_CIPHER_CTX_new;

    //numerical example taken from RFC9001 A.2
    auto sample = cast(ubyte[]) hexString!"d1b1c98dd7689fb8ec11d242b123dc9b";
    auto key = cast(ubyte[]) hexString!"9f50449e04a0e810283a1e9933adedd2";
    ubyte[32] mask;
    ecbEncrypt(sample, mask, key, ctx);
    assert((mask[0..5]).toHexString!(LetterCase.lower) == "437b9aec36");
    
    EVP_CIPHER_CTX_free(ctx);
}

ubyte[] ecbDecrypt(ubyte[] ciphertext, ubyte[] plaintext, ubyte[] key,
                    EVP_CIPHER_CTX* ctx,
                    const(EVP_CIPHER)* aes = EVP_aes_128_ecb)
out (result) {
    if (result == null)
        ERR_print_errors_fp(stderr);
} do {
    import deimos.openssl.evp : EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_DecryptFinal_ex;
    int len, plaintext_len;
    if (EVP_DecryptInit_ex(ctx, aes, null, key.ptr, null) < 1)
        return null;
    if (EVP_DecryptUpdate(ctx, plaintext.ptr, &len, ciphertext.ptr,
                                            cast(int) ciphertext.length) < 1)
        return null;
    if (EVP_DecryptFinal_ex(ctx, plaintext[len..$].ptr, &len) != 1)
        return null;
    plaintext_len += len;

    return plaintext[0..plaintext_len];
}

int generateKeyPair(out ubyte[] privateKey, out ubyte[] publicKey)
out (result) {
    if (result < 1)
        ERR_print_errors_fp(stderr);
} do {
    import deimos.openssl.evp : EVP_PKEY_CTX, EVP_PKEY_X25519,
                                EVP_PKEY_derive, EVP_PKEY_derive_init,
                                EVP_PKEY_HKDF, EVP_PKEY_CTX_new_id,
                                EVP_PKEY_keygen, EVP_PKEY_keygen_init,
                                EVP_PKEY_CTX_free,
                                EVP_PKEY_get_raw_private_key,
                                EVP_PKEY_get_raw_public_key;
    EVP_PKEY* pkey = null;
    auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, null);

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);

    ulong len = 32;

    if (EVP_PKEY_get_raw_private_key(pkey, privateKey.ptr, &len) < 1)
        return -1;
    if (EVP_PKEY_get_raw_public_key(pkey, publicKey.ptr, &len) < 1)
        return -1;

    EVP_PKEY_CTX_free(pctx);
    return 1;
}

import deimos.openssl.evp : EVP_PKEY;

int generateSharedKey(ubyte[] publicPeerKey, EVP_PKEY* pkey,
                                                    out ubyte[] sharedKey)
out (result) {
    if (result < 1)
        ERR_print_errors_fp(stderr);
} do {
    ulong len = 32;
    import deimos.openssl.evp : EVP_PKEY_CTX_new, EVP_PKEY_derive_set_peer,
                                EVP_PKEY_derive, EVP_PKEY_CTX_free,
                                EVP_PKEY_new_raw_private_key;

    import deimos.openssl.ssl : NID_X25519;

    auto pctx = EVP_PKEY_CTX_new(pkey, null);
    if (EVP_PKEY_derive_set_peer(pctx, EVP_PKEY_new_raw_private_key(NID_X25519, null,
                                   publicPeerKey.ptr, len)) < 1)
        return -1;
    if (EVP_PKEY_derive(pctx, sharedKey.ptr, &len) < 1)
        return -1;
    EVP_PKEY_CTX_free(pctx);
    return 1;
}

int digest(ubyte[] message, ubyte[] digest, const(EVP_MD)* md = EVP_sha256)
out (result) {
    if (result < 1)
        ERR_print_errors_fp(stderr);
} do {
    import deimos.openssl.evp : EVP_DigestInit, EVP_DigestUpdate,
                                EVP_DigestFinal_ex, EVP_MD_CTX_new,
                                EVP_MD_CTX_destroy;
    auto ctx = EVP_MD_CTX_new();
    uint sha256digestLen;
    if (EVP_DigestInit(ctx, md) < 1)
        return -1;
    if (EVP_DigestUpdate(ctx, message.ptr, message.length) < 1)
        return -1;
    if (EVP_DigestFinal_ex(ctx, digest.ptr, &sha256digestLen) < 1)
        return -1;
    EVP_MD_CTX_destroy(ctx);
    return 1;
}

bool verifyCertficate(ubyte[] handshakeHash, ubyte[] signature, EVP_PKEY* publicKey,
                        const(EVP_MD)* md = EVP_sha256)
{
    // https://www.rfc-editor.org/rfc/rfc8446.html#page-69
    import deimos.openssl.evp : EVP_MD_CTX_create, EVP_DigestVerifyInit,
                                EVP_DigestVerifyUpdate, EVP_DigestVerifyFinal,
                                EVP_MD_CTX_destroy, EVP_MD_CTX;

    ubyte[] toSign;
    import std.array : replicate;
    auto padding = replicate(" ", 64);
    toSign ~= padding;
    toSign ~= "TLS 1.3, server CertificateVerify";
    toSign ~= 0x0;
    toSign ~= handshakeHash;

    EVP_MD_CTX *mdctx;

    mdctx = EVP_MD_CTX_create();

    EVP_DigestVerifyInit(mdctx, null, md, null, publicKey);

    EVP_DigestVerifyUpdate(mdctx, toSign.ptr, toSign.length);

    bool isValid;
    if (EVP_DigestVerifyFinal(mdctx, signature.ptr, signature.length) == 1)
        isValid = true;
    else
        isValid = false;

    EVP_MD_CTX_destroy(mdctx);
    return isValid;
}
