/* sha1.h */

#ifndef __SHA1_INCLUDE_

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define SHA1_SIGNATURE_SIZE 20

void SHA1_Transform(unsigned long[5], const unsigned char[64]);
void SHA1_Init(SHA1_CTX *);
void SHA1_Update(SHA1_CTX *, const unsigned char *, unsigned int);
void SHA1_Final(unsigned char[20], SHA1_CTX *);

#define __SHA1_INCLUDE_
#endif /* __SHA1_INCLUDE_ */
