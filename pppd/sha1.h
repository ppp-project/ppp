/* sha1.h */

#ifndef __SHA1_INCLUDE_

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define SHA1_SIGNATURE_SIZE 20

extern void SHA1_Init(SHA1_CTX *);
extern void SHA1_Update(SHA1_CTX *, const unsigned char *, unsigned int);
extern void SHA1_Final(unsigned char[SHA1_SIGNATURE_SIZE], SHA1_CTX *);

#define __SHA1_INCLUDE_
#endif /* __SHA1_INCLUDE_ */
