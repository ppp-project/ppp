/*
 * pppcrypt.c - PPP/DES linkage for MS-CHAP and EAP SRP-SHA1
 *
 * Extracted from chap_ms.c by James Carlson.
 * Updated to better reflect RFC2759 by Eivind Naess
 *
 * Copyright (c) 2022 Eivind Naess.  All rights reserved.
 * Copyright (c) 1995 Eric Rosenquist.  All rights reserved.
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
#ifndef PPP_PPPCRYPT_H
#define	PPP_PPPCRYPT_H

#include "pppdconf.h"

/**
 * This is the DES encrypt functions as described by RFC2759.
 * 
 * Parameters:
 * unsigned char *clear:
 *      A 8 byte input array to be encrypted
 * 
 * unsigned char *key: 
 *      A raw 7-byte array to be expanded to 8 with odd-parity
 *
 * unsigned char *cipher:
 *      A 8 byte outut array providing space for the output data
 *
 * DesEncrypt returns 1 on success
 */
int DesEncrypt(unsigned char *clear, unsigned char *key, 
        unsigned char *cipher);

/**
 * This is the DES decrypt functions as described by RFC2759.
 * 
 * Parameters:
 * unsigned char *cipher:
 *      A 8 byte input array to be decrypted
 *
 * unsigned char *key: 
 *      A raw 7-byte array to be expanded to a 8-byte key with odd-parity
 *
 * unsigned char *clear:
 *      A 8 byte output array providing space for the output data
 *
 * DesDecrypt returns 1 on success
 */
int DesDecrypt(unsigned char *cipher, unsigned char *key, 
        unsigned char *clear);

#endif /* PPP_PPPCRYPT_H */
