/* sha1.h */

#ifndef __SHA1_INCLUDE_

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
} SHA_CTX;

extern void SHA1_Init(SHA_CTX *context);
extern void SHA1_Update(SHA_CTX *context, const unsigned char *data, size_t len);
extern void SHA1_Final(unsigned char *data, SHA_CTX *context);

#define __SHA1_INCLUDE_
#endif /* __SHA1_INCLUDE_ */

