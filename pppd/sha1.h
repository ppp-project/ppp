/* sha1.h */

#include "pppdconf.h"

#ifndef __SHA1_INCLUDE_
#define __SHA1_INCLUDE_

#ifndef USE_SHA
#include <openssl/sha.h>

#define SHA1_CTX SHA_CTX
#define SHA1_SIGNATURE_SIZE SHA_DIGEST_LENGTH

#else

#ifndef SHA1_SIGNATURE_SIZE
#ifdef SHA_DIGESTSIZE
#define SHA1_SIGNATURE_SIZE SHA_DIGESTSIZE
#else
#define SHA1_SIGNATURE_SIZE 20
#endif
#endif

typedef struct {
    u_int32_t state[5];
    u_int32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

extern void SHA1_Init(SHA1_CTX *);
extern void SHA1_Update(SHA1_CTX *, const unsigned char *, unsigned int);
extern void SHA1_Final(unsigned char[SHA1_SIGNATURE_SIZE], SHA1_CTX *);

#endif /* USE_SHA */
#endif /* __SHA1_INCLUDE_ */
