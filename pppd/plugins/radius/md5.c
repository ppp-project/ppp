/*
 * $Id: md5.c,v 1.1 2004/11/14 07:26:26 paulus Exp $
 */
#include <stddef.h>

#include <pppd/crypto.h>

int rc_md5_calc(unsigned char *out, const unsigned char *in, unsigned int inl)
{
    int retval = 0;
    int outl = MD5_DIGEST_LENGTH;

    PPP_MD_CTX *ctx = PPP_MD_CTX_new();
    if (ctx) {

        if (PPP_DigestInit(ctx, PPP_md5())) {

            if (PPP_DigestUpdate(ctx, in, inl)) {

                if (PPP_DigestFinal(ctx, out, &outl)) {

                    retval = 1;
                }
            }
        }

        PPP_MD_CTX_free(ctx);
    }
    return retval;
}
