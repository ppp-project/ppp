/*
 * chap_ms.h - Challenge Handshake Authentication Protocol definitions.
 *
 * Copyright (c) 1995 Eric Rosenquist, Strata Software Limited.
 * http://www.strataware.com/
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Eric Rosenquist.  The name of the author may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * $Id: chap_ms.h,v 1.6 2002/04/02 13:54:59 dfs Exp $
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
