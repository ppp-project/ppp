/*
 * chap_ms.c - Microsoft MS-CHAP compatible implementation.
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
 */

/*
 * Modifications by Lauri Pesonen / lpesonen@clinet.fi, april 1997
 *
 *   Implemented LANManager type password response to MS-CHAP challenges.
 *   Now pppd provides both NT style and LANMan style blocks, and the
 *   prefered is set by option "ms-lanman". Default is to use NT.
 *   The hash text (StdText) was taken from Win95 RASAPI32.DLL.
 *
 *   You should also use DOMAIN\\USERNAME as described in README.MSCHAP80
 */

/*
 * Modifications by Frank Cusack, frank@google.com, March 2002.
 *
 *   Implemented MS-CHAPv2 functionality.  Heavily based on
 *   sample implementation in RFC 2759.
 */

#define RCSID	"$Id: chap_ms.c,v 1.18 2002/03/05 15:14:04 dfs Exp $"

#ifdef CHAPMS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#include "pppd.h"
#include "chap.h"
#include "chap_ms.h"
#include "md4.h"
#include "sha1.h"

#ifndef USE_CRYPT
#include <des.h>
#endif

static const char rcsid[] = RCSID;


static void	ChallengeHash __P((u_char[16], u_char *, char *, u_char[8]));
static void	ascii2unicode __P((char[], int, u_char[]));
static void	NTPasswordHash __P((char *, int, u_char[MD4_SIGNATURE_SIZE]));
static void	ChallengeResponse __P((u_char *, u_char *, u_char[24]));
static void	DesEncrypt __P((u_char *, u_char *, u_char[8]));
static void	MakeKey __P((u_char *, u_char *));
static u_char	Get7Bits __P((u_char *, int));
static void	ChapMS_NT __P((u_char *, char *, int, u_char[24]));
static void	ChapMS2_NT __P((char *, u_char[16], char *, char *, int,
				u_char[24]));
static void	GenerateAuthenticatorResponse __P((char*, int, u_char[24],
						   u_char[16], u_char *,
						   char *, u_char[41]));
#ifdef MSLANMAN
static void	ChapMS_LANMan __P((u_char *, char *, int, MS_ChapResponse *));
#endif

#ifdef USE_CRYPT
static void	Expand __P((u_char *, u_char *));
static void	Collapse __P((u_char *, u_char *));
#endif

extern double drand48 __P((void));

#ifdef MSLANMAN
bool	ms_lanman = 0;    	/* Use LanMan password instead of NT */
			  	/* Has meaning only with MS-CHAP challenges */
#endif

static void
ChallengeResponse(u_char *challenge,
		  u_char PasswordHash[MD4_SIGNATURE_SIZE],
		  u_char response[24])
{
    char    ZPasswordHash[21];

    BZERO(ZPasswordHash, sizeof(ZPasswordHash));
    BCOPY(PasswordHash, ZPasswordHash, MD4_SIGNATURE_SIZE);

#if 0
    dbglog("ChallengeResponse - ZPasswordHash %.*B",
	   sizeof(ZPasswordHash), ZPasswordHash);
#endif

    DesEncrypt(challenge, ZPasswordHash +  0, &response[0]);
    DesEncrypt(challenge, ZPasswordHash +  7, &response[8]);
    DesEncrypt(challenge, ZPasswordHash + 14, &response[16]);

#if 0
    dbglog("ChallengeResponse - response %.24B", response);
#endif
}


#ifdef USE_CRYPT
static void
DesEncrypt(u_char *clear, u_char *key, u_char cipher[8])
{
    u_char des_key[8];
    u_char crypt_key[66];
    u_char des_input[66];

    MakeKey(key, des_key);

    Expand(des_key, crypt_key);
    setkey(crypt_key);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet input : %.8B", clear));
#endif

    Expand(clear, des_input);
    encrypt(des_input, 0);
    Collapse(des_input, cipher);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet output: %.8B", cipher));
#endif
}

#else /* USE_CRYPT */

static void
DesEncrypt(u_char *clear, u_char *key, u_char cipher[8])
{
    des_cblock		des_key;
    des_key_schedule	key_schedule;

    MakeKey(key, des_key);

    des_set_key(&des_key, key_schedule);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet input : %.8B", clear));
#endif

    des_ecb_encrypt((des_cblock *)clear, (des_cblock *)cipher, key_schedule, 1);

#if 0
    CHAPDEBUG((LOG_INFO, "DesEncrypt: 8 octet output: %.8B", cipher));
#endif
}

#endif /* USE_CRYPT */


static u_char Get7Bits(u_char *input, int startBit)
{
    register unsigned int	word;

    word  = (unsigned)input[startBit / 8] << 8;
    word |= (unsigned)input[startBit / 8 + 1];

    word >>= 15 - (startBit % 8 + 7);

    return word & 0xFE;
}

#ifdef USE_CRYPT

/* in == 8-byte string (expanded version of the 56-bit key)
 * out == 64-byte string where each byte is either 1 or 0
 * Note that the low-order "bit" is always ignored by by setkey()
 */
static void Expand(u_char *in, u_char *out)
{
        int j, c;
        int i;

        for(i = 0; i < 64; in++){
		c = *in;
                for(j = 7; j >= 0; j--)
                        *out++ = (c >> j) & 01;
                i += 8;
        }
}

/* The inverse of Expand
 */
static void Collapse(u_char *in, u_char *out)
{
        int j;
        int i;
	unsigned int c;

	for (i = 0; i < 64; i += 8, out++) {
	    c = 0;
	    for (j = 7; j >= 0; j--, in++)
		c |= *in << j;
	    *out = c & 0xff;
	}
}
#endif

static void MakeKey(u_char *key, u_char *des_key)
{
    des_key[0] = Get7Bits(key,  0);
    des_key[1] = Get7Bits(key,  7);
    des_key[2] = Get7Bits(key, 14);
    des_key[3] = Get7Bits(key, 21);
    des_key[4] = Get7Bits(key, 28);
    des_key[5] = Get7Bits(key, 35);
    des_key[6] = Get7Bits(key, 42);
    des_key[7] = Get7Bits(key, 49);

#ifndef USE_CRYPT
    des_set_odd_parity((des_cblock *)des_key);
#endif

#if 0
    CHAPDEBUG((LOG_INFO, "MakeKey: 56-bit input : %.7B", key));
    CHAPDEBUG((LOG_INFO, "MakeKey: 64-bit output: %.8B", des_key));
#endif
}


static void
ChallengeHash(u_char PeerChallenge[16], u_char *rchallenge,
	      char *username, u_char Challenge[8])
    
{
    SHA1_CTX	sha1Context;
    u_char	sha1Hash[SHA1_SIGNATURE_SIZE];

    SHA1_Init(&sha1Context);
    SHA1_Update(&sha1Context, PeerChallenge, 16);
    SHA1_Update(&sha1Context, rchallenge, 16);
    SHA1_Update(&sha1Context, username, strlen(username));
    SHA1_Final(sha1Hash, &sha1Context);

    BCOPY(sha1Hash, Challenge, 8);
}

/*
 * Convert the ASCII version of the password to Unicode.
 * This implicitly supports 8-bit ISO8859/1 characters.
 * This gives us the little-endian representation, which
 * is assumed by all M$ CHAP RFCs.  (Unicode byte ordering
 * is machine-dependent.)
 */
static void
ascii2unicode(char ascii[], int ascii_len, u_char unicode[])
{
    int i;

    BZERO(unicode, ascii_len * 2);
    for (i = 0; i < ascii_len; i++)
	unicode[i * 2] = (u_char) ascii[i];
}

static void
NTPasswordHash(char *secret, int secret_len, u_char hash[MD4_SIGNATURE_SIZE])
{
#ifdef __NetBSD__
    /* NetBSD uses the libc md4 routines which take bytes instead of bits */
    int			mdlen = secret_len;
#else
    int			mdlen = secret_len * 8;
#endif
    MD4_CTX		md4Context;

    MD4Init(&md4Context);
    MD4Update(&md4Context, secret, mdlen);
    MD4Final(hash, &md4Context);

}

static void
ChapMS_NT(u_char *rchallenge, char *secret, int secret_len,
	  u_char NTResponse[24])
{
    u_char	unicodePassword[MAX_NT_PASSWORD * 2];
    u_char	PasswordHash[MD4_SIGNATURE_SIZE];

    /* Hash the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);

    ChallengeResponse(rchallenge, PasswordHash, NTResponse);
}

static void
ChapMS2_NT(char *rchallenge, u_char PeerChallenge[16], char *username,
	   char *secret, int secret_len, u_char NTResponse[24])
{
    u_char	unicodePassword[MAX_NT_PASSWORD * 2];
    u_char	PasswordHash[MD4_SIGNATURE_SIZE];
    u_char	Challenge[8];

    ChallengeHash(PeerChallenge, rchallenge, username, Challenge);

    /* Hash the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);

    ChallengeResponse(Challenge, PasswordHash, NTResponse);
}

#ifdef MSLANMAN
static u_char *StdText = (u_char *)"KGS!@#$%"; /* key from rasapi32.dll */

static void
ChapMS_LANMan(u_char *rchallenge, char *secret, int secret_len,
	      u_char LMResponse[24])
{
    int			i;
    u_char		UcasePassword[MAX_NT_PASSWORD]; /* max is actually 14 */
    u_char		PasswordHash[MD4_SIGNATURE_SIZE];

    /* LANMan password is case insensitive */
    BZERO(UcasePassword, sizeof(UcasePassword));
    for (i = 0; i < secret_len; i++)
       UcasePassword[i] = (u_char)toupper(secret[i]);
    DesEncrypt( StdText, UcasePassword + 0, PasswordHash + 0 );
    DesEncrypt( StdText, UcasePassword + 7, PasswordHash + 8 );
    ChallengeResponse(rchallenge, PasswordHash, LMResponse);
}
#endif


static void
GenerateAuthenticatorResponse(char *secret, int secret_len,
			      u_char NTResponse[24], u_char PeerChallenge[16],
			      u_char *rchallenge, char *username,
			      u_char authResponse[MS_AUTH_RESPONSE_LENGTH+1])
{
    /*
     * "Magic" constants used in response generation, from RFC 2759.
     */
    u_char Magic1[39] = /* "Magic server to client signing constant" */
	{0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
	 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
	 0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
	 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};
    u_char Magic2[41] = /* "Pad to make it do more than one iteration" */
	{0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
	 0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
	 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
	 0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
	 0x6E};

    int		i;
    SHA1_CTX	sha1Context;
    u_char	unicodePassword[MAX_NT_PASSWORD * 2];
    u_char	PasswordHash[MD4_SIGNATURE_SIZE];
    u_char	PasswordHashHash[MD4_SIGNATURE_SIZE];
    u_char	Digest[SHA1_SIGNATURE_SIZE];
    u_char	Challenge[8];

    /* Hash (x2) the Unicode version of the secret (== password). */
    ascii2unicode(secret, secret_len, unicodePassword);
    NTPasswordHash(unicodePassword, secret_len * 2, PasswordHash);
    NTPasswordHash(PasswordHash, sizeof(PasswordHash), PasswordHashHash);

    SHA1_Init(&sha1Context);
    SHA1_Update(&sha1Context, PasswordHashHash, sizeof(PasswordHashHash));
    SHA1_Update(&sha1Context, NTResponse, 24);
    SHA1_Update(&sha1Context, Magic1, sizeof(Magic1));
    SHA1_Final(Digest, &sha1Context);

    ChallengeHash(PeerChallenge, rchallenge, username, Challenge);

    SHA1_Init(&sha1Context);
    SHA1_Update(&sha1Context, Digest, sizeof(Digest));
    SHA1_Update(&sha1Context, Challenge, sizeof(Challenge));
    SHA1_Update(&sha1Context, Magic2, sizeof(Magic2));
    SHA1_Final(Digest, &sha1Context);

    /* Convert to ASCII hex string. */
    for (i = 0; i < MAX((MS_AUTH_RESPONSE_LENGTH / 2), sizeof(Digest)); i++)
	sprintf(&authResponse[i * 2], "%02X", Digest[i]);
}


void
ChapMS(chap_state *cstate, u_char *rchallenge, char *secret, int secret_len,
       MS_ChapResponse *response)
{
#if 0
    CHAPDEBUG((LOG_INFO, "ChapMS: secret is '%.*s'", secret_len, secret));
#endif
    BZERO(response, sizeof(response));

    /* Calculate both always */
    ChapMS_NT(rchallenge, secret, secret_len, response->NTResp);

#ifdef MSLANMAN
    ChapMS_LANMan(rchallenge, secret, secret_len, response);

    /* prefered method is set by option  */
    response->UseNT[0] = !ms_lanman;
#else
    response->UseNT[0] = 1;
#endif

}


/*
 * If PeerChallenge is NULL, one is generated and response->PeerChallenge
 * is filled in.  Call this way when generating a response.
 * If PeerChallenge is supplied, it is copied into response->PeerChallenge.
 * Call this way when verifying a response.
 *
 * response->PeerChallenge is then used for calculation of the
 * Authenticator Response.
 */
void
ChapMS2(chap_state *cstate, u_char *rchallenge, u_char *PeerChallenge,
	char *user, char *secret, int secret_len, MS_Chap2Response *response,
	u_char authResponse[MS_AUTH_RESPONSE_LENGTH+1])
{
    u_char *p = response->PeerChallenge;
    int i;

    BZERO(response, sizeof(response));

    /* Generate the Peer-Challenge if requested, or copy it if supplied. */
    if (!PeerChallenge)
	for (i = 0; i < sizeof(response->PeerChallenge); i++)
	    *p++ = (u_char) (drand48() * 0xff);
    else
	BCOPY(PeerChallenge, response->PeerChallenge,
	      sizeof(response->PeerChallenge));

    /* Generate the NT-Response */
    ChapMS2_NT(rchallenge, response->PeerChallenge, user,
	       secret, secret_len, response->NTResp);

    /* Generate the Authenticator Response. */
    GenerateAuthenticatorResponse(secret, secret_len, response->NTResp,
				  response->PeerChallenge, rchallenge,
				  user, authResponse);
}


#endif /* CHAPMS */
