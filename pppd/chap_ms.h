/*
 * chap_ms.h - Challenge Handshake Authentication Protocol definitions.
 *
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
 *
 * $Id: chap_ms.h,v 1.8 2002/12/23 23:24:37 fcusack Exp $
 */

#ifndef __CHAPMS_INCLUDE__

#define MD4_SIGNATURE_SIZE	16	/* 16 bytes in a MD4 message digest */
#define MAX_NT_PASSWORD		256	/* Max (Unicode) chars in an NT pass */

#define MS_CHAP_RESPONSE_LEN	49	/* Response length for MS-CHAP */
#define MS_CHAP2_RESPONSE_LEN	49	/* Response length for MS-CHAPv2 */

/* E=eeeeeeeeee error codes for MS-CHAP failure messages. */
#define MS_CHAP_ERROR_RESTRICTED_LOGON_HOURS	646
#define MS_CHAP_ERROR_ACCT_DISABLED		647
#define MS_CHAP_ERROR_PASSWD_EXPIRED		648
#define MS_CHAP_ERROR_NO_DIALIN_PERMISSION	649
#define MS_CHAP_ERROR_AUTHENTICATION_FAILURE	691
#define MS_CHAP_ERROR_CHANGING_PASSWORD		709

/*
 * Use MS_CHAP_RESPONSE_LEN, rather than sizeof(MS_ChapResponse),
 * in case this struct gets padded.
 */
typedef struct {
    u_char LANManResp[24];
    u_char NTResp[24];
    u_char UseNT[1];		/* If 1, ignore the LANMan response field */
} MS_ChapResponse;

/*
 * Use MS_CHAP2_RESPONSE_LEN, rather than sizeof(MS_Chap2Response),
 * in case this struct gets padded.
 */
typedef struct {
    u_char PeerChallenge[16];
    u_char Reserved[8];		/* Must be zero */
    u_char NTResp[24];
    u_char Flags[1];		/* Must be zero */
} MS_Chap2Response;

#ifdef MPPE
#include <net/ppp-comp.h>	/* MPPE_MAX_KEY_LEN */
extern u_char mppe_send_key[MPPE_MAX_KEY_LEN];
extern u_char mppe_recv_key[MPPE_MAX_KEY_LEN];
extern int mppe_keys_set;
#endif

/* Are we the authenticator or authenticatee?  For MS-CHAPv2 key derivation. */
#define MS_CHAP2_AUTHENTICATEE 0
#define MS_CHAP2_AUTHENTICATOR 1

#include "chap.h" /* chap_state, et al */
void ChapMS __P((chap_state *, u_char *, char *, int, MS_ChapResponse *));
void ChapMS2 __P((chap_state *, u_char *, u_char *, char *, char *, int,
		  MS_Chap2Response *, u_char[MS_AUTH_RESPONSE_LENGTH+1], int));
#ifdef MPPE
void mppe_set_keys __P((u_char *, u_char[MD4_SIGNATURE_SIZE]));
#endif

#define __CHAPMS_INCLUDE__
#endif /* __CHAPMS_INCLUDE__ */
