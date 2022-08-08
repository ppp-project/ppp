/* ppp-crypto.c - Generic API for access to crypto/digest functions.
 *
 * Copyright (c) 2022 Eivind Næss. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "ppp-crypto.h"
#include "ppp-crypto-priv.h"

#ifdef PPP_WITH_OPENSSL
#include <openssl/opensslv.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
struct crypto_ctx {

    OSSL_PROVIDER *legacy;
    OSSL_PROVIDER *provider;
} g_crypto_ctx;
#endif

PPP_MD_CTX *PPP_MD_CTX_new()
{
    return (PPP_MD_CTX*) calloc(1, sizeof(PPP_MD_CTX));
}

void PPP_MD_CTX_free(PPP_MD_CTX* ctx)
{
    if (ctx) {
        if (ctx->md.clean_fn) {
            ctx->md.clean_fn(ctx);
        }
        free(ctx);
    }
}

int PPP_DigestInit(PPP_MD_CTX *ctx, const PPP_MD *type)
{
    if (ctx) {
        ctx->md = *type;
        if (ctx->md.init_fn) {
            return ctx->md.init_fn(ctx);
        }
    }
    return 0;
}

int PPP_DigestUpdate(PPP_MD_CTX *ctx, const void *data, size_t length)
{
    if (ctx && ctx->md.update_fn) {
        return ctx->md.update_fn(ctx, data, length);
    }
    return 0;
}

int PPP_DigestFinal(PPP_MD_CTX *ctx, unsigned char *out, unsigned int *outlen)
{
    if (ctx && ctx->md.final_fn) {
        return ctx->md.final_fn(ctx, out, outlen);
    }
    return 0;
}

PPP_CIPHER_CTX *PPP_CIPHER_CTX_new(void)
{
    return calloc(1, sizeof(PPP_CIPHER_CTX));
}

void PPP_CIPHER_CTX_free(PPP_CIPHER_CTX *ctx)
{
    if (ctx) {
        if (ctx->cipher.clean_fn) {
            ctx->cipher.clean_fn(ctx);
        }
        memset(ctx->iv, 0, sizeof(ctx->iv));
        memset(ctx->key, 0, sizeof(ctx->key));
        free(ctx);
    }
}

int PPP_CipherInit(PPP_CIPHER_CTX *ctx, const PPP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, int encr)
{
    if (ctx && cipher) {
        ctx->is_encr = encr;
        ctx->cipher = *cipher;
        if (ctx->cipher.init_fn) {
            ctx->cipher.init_fn(ctx, key, iv);
        }
        return 1;
    }
    return 0;
}

int PPP_CipherUpdate(PPP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    if (ctx && ctx->cipher.update_fn) {
        return ctx->cipher.update_fn(ctx, out, outl, in, inl);
    }
    return 0;
}

int PPP_CipherFinal(PPP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx && ctx->cipher.final_fn) {
        return ctx->cipher.final_fn(ctx, out, outl);
    }
    return 0;
}

void PPP_CIPHER_CTX_set_cipher_data(PPP_CIPHER_CTX *ctx, const unsigned char *key)
{
    if (ctx && ctx->cipher.set_key_fn) {
        ctx->cipher.set_key_fn(ctx, key);
    }
}


int PPP_crypto_init()
{
    int retval = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    g_crypto_ctx.legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (g_crypto_ctx.legacy == NULL)
    {
        goto done;
    }

    g_crypto_ctx.provider = OSSL_PROVIDER_load(NULL, "default");
    if (g_crypto_ctx.provider == NULL)
    {
        goto done;
    }
#endif
    retval = 1;

done:

    return retval;
}

int PPP_crypto_deinit()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (g_crypto_ctx.legacy) {
        OSSL_PROVIDER_unload(g_crypto_ctx.legacy);
        g_crypto_ctx.legacy = NULL;
    }

    if (g_crypto_ctx.provider) {
        OSSL_PROVIDER_unload(g_crypto_ctx.provider);
        g_crypto_ctx.provider = NULL;
    }
#endif
    return 1;
}

#ifdef UNIT_TEST
#include <stdio.h>

int test_md4()
{
    PPP_MD_CTX* ctx = NULL;
    int success = 0;

    unsigned char data[84] = {
        0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
        0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69,
        0x64, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
        0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
        0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	    0x6b, 0x65, 0x79, 0x2e
    };

    unsigned int  hash_len;
    unsigned char hash[MD4_DIGEST_LENGTH];
    unsigned char result[MD4_DIGEST_LENGTH] = {
        0x58, 0xcb, 0x37, 0x91, 0x1d, 0x06, 0x7b, 0xdf,
        0xfd, 0x48, 0x6d, 0x87, 0x4a, 0x35, 0x5b, 0xd4
    };

    ctx = PPP_MD_CTX_new();
    if (ctx) {

        if (PPP_DigestInit(ctx, PPP_md4())) {

            if (PPP_DigestUpdate(ctx, &data, sizeof(data))) {

                hash_len = sizeof(hash);
                if (PPP_DigestFinal(ctx, hash, &hash_len)) {

                    if (memcmp(hash, result, MD4_DIGEST_LENGTH) == 0) {
                        success = 1;
                    }
                }
            }
        }
        PPP_MD_CTX_free(ctx);
    }

    return success;
}

int test_md5()
{
    PPP_MD_CTX* ctx = NULL;
    int success = 0;

    unsigned char data[84] = {
        0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
        0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69,
        0x64, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
        0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
        0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	    0x6b, 0x65, 0x79, 0x2e
    };

    unsigned int  hash_len;
    unsigned char hash[MD5_DIGEST_LENGTH];
    unsigned char result[MD5_DIGEST_LENGTH] = {
        0x8b, 0xe3, 0x5e, 0x2c, 0x9f, 0x95, 0xbf, 0x4e,
        0x16, 0xe4, 0x53, 0xbe, 0x52, 0xf4, 0xbc, 0x4e
    };

    ctx = PPP_MD_CTX_new();
    if (ctx) {

        if (PPP_DigestInit(ctx, PPP_md5())) {

            if (PPP_DigestUpdate(ctx, &data, sizeof(data))) {

                hash_len = sizeof(hash);
                if (PPP_DigestFinal(ctx, hash, &hash_len)) {

                    if (memcmp(hash, result, MD5_DIGEST_LENGTH) == 0) {
                        success = 1;
                    }
                }
            }
        }
        PPP_MD_CTX_free(ctx);
    }

    return success;
}

int test_sha()
{
    PPP_MD_CTX* ctx = NULL;
    int success = 0;

    unsigned char data[84] = {
        0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
        0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69,
        0x64, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
        0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
        0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	    0x6b, 0x65, 0x79, 0x2e
    };

    unsigned int  hash_len;
    unsigned char hash[SHA_DIGEST_LENGTH];
    unsigned char result[SHA_DIGEST_LENGTH] = {
        0xa8, 0x03, 0xae, 0x21, 0x30, 0xd8, 0x40, 0xbe,
        0x27, 0xa3, 0x47, 0xc7, 0x7a, 0x90, 0xe6, 0xa3,
        0x5b, 0xd5, 0x0e, 0x45
    };

    ctx = PPP_MD_CTX_new();
    if (ctx) {

        if (PPP_DigestInit(ctx, PPP_sha1())) {

            if (PPP_DigestUpdate(ctx, &data, sizeof(data))) {

                hash_len = sizeof(hash);
                if (PPP_DigestFinal(ctx, hash, &hash_len)) {

                    if (memcmp(hash, result, SHA_DIGEST_LENGTH) == 0) {
                        success = 1;
                    }
                }
            }
        }
        PPP_MD_CTX_free(ctx);
    }

    return success;
}

int test_des_encrypt()
{
    PPP_CIPHER_CTX* ctx = NULL;
    int success = 0;

    unsigned char key[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    unsigned char plain[80] = {
        0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
        0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69,
        0x64, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
        0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
        0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20
    };
    unsigned char expect[80] = {
        0x5d, 0xa7, 0x47, 0xc5, 0x1a, 0xb1, 0x71, 0xff,
        0xc8, 0x45, 0x7c, 0xa7, 0x07, 0xec, 0x4b, 0x13,
        0x47, 0x55, 0x77, 0xbc, 0xcf, 0x71, 0xd9, 0x27,
        0x23, 0x12, 0x2a, 0x17, 0x20, 0xad, 0xc1, 0x19,
        0x3e, 0x74, 0x38, 0x29, 0x48, 0xb0, 0xd2, 0xe2,
        0x18, 0x45, 0xdd, 0x8a, 0x9b, 0x8d, 0x40, 0xec,
        0x9e, 0x0c, 0x41, 0xa3, 0x36, 0x40, 0xf5, 0x91,
        0x41, 0x44, 0xde, 0xa1, 0xb5, 0x9d, 0x39, 0x99,
        0x23, 0x12, 0x2a, 0x17, 0x20, 0xad, 0xc1, 0x19,
        0xee, 0xe3, 0xbe, 0x0b, 0x83, 0x36, 0xe1, 0x25
    };

    unsigned char cipher[80] = {};
    int cipher_len = 0;
    int offset = 0;


    ctx = PPP_CIPHER_CTX_new();
    if (ctx) {

        if (PPP_CipherInit(ctx, PPP_des_ecb(), key, NULL, 1)) {

            if (PPP_CipherUpdate(ctx, cipher, &cipher_len, plain, sizeof(plain))) {

                offset += cipher_len;

                if (PPP_CipherFinal(ctx, cipher+offset, &cipher_len)) {

                    if (memcmp(cipher, expect, 80) == 0) {

                        success = 1;
                    }
                }
            }
        }
        PPP_CIPHER_CTX_free(ctx);
    }

    return success;
}


int test_des_decrypt()
{
    PPP_CIPHER_CTX* ctx = NULL;
    int success = 0;

    unsigned char key[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    unsigned char cipher[80] = {
        0x5d, 0xa7, 0x47, 0xc5, 0x1a, 0xb1, 0x71, 0xff,
        0xc8, 0x45, 0x7c, 0xa7, 0x07, 0xec, 0x4b, 0x13,
        0x47, 0x55, 0x77, 0xbc, 0xcf, 0x71, 0xd9, 0x27,
        0x23, 0x12, 0x2a, 0x17, 0x20, 0xad, 0xc1, 0x19,
        0x3e, 0x74, 0x38, 0x29, 0x48, 0xb0, 0xd2, 0xe2,
        0x18, 0x45, 0xdd, 0x8a, 0x9b, 0x8d, 0x40, 0xec,
        0x9e, 0x0c, 0x41, 0xa3, 0x36, 0x40, 0xf5, 0x91,
        0x41, 0x44, 0xde, 0xa1, 0xb5, 0x9d, 0x39, 0x99,
        0x23, 0x12, 0x2a, 0x17, 0x20, 0xad, 0xc1, 0x19,
        0xee, 0xe3, 0xbe, 0x0b, 0x83, 0x36, 0xe1, 0x25
    };

    unsigned char expect[80] = {
        0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63,
        0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69,
        0x64, 0x65, 0x2c, 0x20, 0x74, 0x68, 0x69, 0x73,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
        0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
        0x73, 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74,
        0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20
    };

    unsigned char plain[80] = {};
    int outlen = 0;
    int offset = 0;

    ctx = PPP_CIPHER_CTX_new();
    if (ctx) {

        if (PPP_CipherInit(ctx, PPP_des_ecb(), key, NULL, 0)) {

            if (PPP_CipherUpdate(ctx, plain, &outlen, cipher, sizeof(cipher))) {

                offset += outlen;

                if (PPP_CipherFinal(ctx, plain+offset, &outlen)) {

                    if (memcmp(plain, expect, 80) == 0) {

                        success = 1;
                    }
                }
            }
        }
        PPP_CIPHER_CTX_free(ctx);
    }

    return success;
}

int main(int argc, char *argv[]) {
    int failure = 0;

    if (!PPP_crypto_init()) {
        printf("Couldn't initialize crypto test\n");
        return -1;
    }

    if (!test_md4()) {
        printf("MD4 test failed\n");
        failure++;
    }

    if (!test_md5()) {
        printf("MD5 test failed\n");
        failure++;
    }

    if (!test_sha()) {
        printf("SHA test failed\n");
        failure++;
    }

    if (!test_des_encrypt()) {
        printf("DES encryption test failed\n");
        failure++;
    }

    if (!test_des_decrypt()) {
        printf("DES decryption test failed\n");
        failure++;
    }

    if (!PPP_crypto_deinit()) {
        printf("Couldn't deinitialize crypto test\n");
        return -1;
    }

    return failure;
}

#endif
