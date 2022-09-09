/* ppp-crypto.h - Generic API for access to crypto/digest functions.
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

#ifndef PPP_CRYPTO_H
#define PPP_CRYPTO_H

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

#ifndef MD4_DIGEST_LENGTH
#define MD4_DIGEST_LENGTH 16
#endif

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

struct _PPP_MD_CTX;
struct _PPP_MD;

typedef struct _PPP_MD_CTX PPP_MD_CTX;
typedef struct _PPP_MD PPP_MD;


PPP_MD_CTX *PPP_MD_CTX_new();
void PPP_MD_CTX_free(PPP_MD_CTX*);


const PPP_MD *PPP_md4(void);
const PPP_MD *PPP_md5(void);
const PPP_MD *PPP_sha1(void);


int PPP_DigestInit(PPP_MD_CTX *ctx,
        const PPP_MD *type);
int PPP_DigestUpdate(PPP_MD_CTX *ctx,
        const void *data, size_t cnt);
int PPP_DigestFinal(PPP_MD_CTX *ctx,
        unsigned char *out, unsigned int *outlen);


struct _PPP_CIPHER_CTX;
struct _PPP_CIPHER;

typedef struct _PPP_CIPHER_CTX PPP_CIPHER_CTX;
typedef struct _PPP_CIPHER PPP_CIPHER;


PPP_CIPHER_CTX *PPP_CIPHER_CTX_new(void);
void PPP_CIPHER_CTX_free(PPP_CIPHER_CTX *ctx);

const PPP_CIPHER *PPP_des_ecb(void);

void PPP_CIPHER_CTX_set_cipher_data(PPP_CIPHER_CTX *ctx,
        const unsigned char *key);

int PPP_CipherInit(PPP_CIPHER_CTX *ctx,
        const PPP_CIPHER *cipher,
        const unsigned char *key,
        const unsigned char *iv,
        int encr);

int PPP_CipherUpdate(PPP_CIPHER_CTX *ctx,
        unsigned char *out, int *outl,
        const unsigned char *in, int inl);

int PPP_CipherFinal(PPP_CIPHER_CTX *ctx,
        unsigned char *out, int *outl);

int PPP_crypto_init();
int PPP_crypto_deinit();

#endif
