/* ans.c - Interface for text2atm and atm2text to ANS */

/* Written 1996-2000 by Werner Almesberger, EPFL-LRC/ICA */


/*
 * This stuff is a temporary hack to avoid using gethostbyname_nsap and such
 * without doing the "full upgrade" to getaddrinfo/getnameinfo. This also
 * serves as an exercise for me to get all the details right before I propose
 * a patch that would eventually end up in libc (and that should therefore be
 * as stable as possible).
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>

#include "atm.h"
#include "atmres.h"


#define MAX_ANSWER 2048
#define MAX_NAME   1024

#define GET16(pos) (((pos)[0] << 8) | (pos)[1])


static int ans(const char *text,int wanted,void *result,int res_len)
{
    unsigned char answer[MAX_ANSWER];
    unsigned char name[MAX_NAME];
    unsigned char *pos,*data,*found;
    int answer_len,name_len,data_len,found_len;
    int questions,answers;

    found_len = 0; /* gcc wants it */
    if ((answer_len = res_search(text,C_IN,wanted,answer,MAX_ANSWER)) < 0)
	return TRY_OTHER;
    /*
     * Response header: id, flags, #queries, #answers, #authority,
     * #additional (all 16 bits)
     */
    pos = answer+12;
    if (answer[3] & 15) return TRY_OTHER; /* rcode != 0 */
    questions = GET16(answer+4);
    if (questions != 1) return TRY_OTHER; /* trouble ... */
    answers = GET16(answer+6);
    if (answers < 1) return TRY_OTHER;
    /*
     * Query: name, type (16), class (16)
     */
    if ((name_len = dn_expand(answer,answer+answer_len,pos,name,MAX_NAME)) < 0)
	return TRY_OTHER;
    pos += name_len;
    if (GET16(pos) != wanted || GET16(pos+2) != C_IN) return TRY_OTHER;
    pos += 4;
    /*
     * Iterate over answers until we find something we like, giving priority
     * to ATMA_AESA (until signaling is fixed to work with E.164 too)
     */
    found = NULL;
    while (answers--) {
	/*
	 * RR: name, type (16), class (16), TTL (32), resource_len (16),
	 * resource_data ...
	 */
	if ((name_len = dn_expand(answer,answer+answer_len,pos,name,MAX_NAME))
	  < 0) return TRY_OTHER;
	pos += name_len;
	data_len = GET16(pos+8);
	data = pos+10;
	pos = data+data_len;
	if (GET16(data-10) != wanted || GET16(data-8) != C_IN || !--data_len)
	    continue;
	switch (wanted) {
            case T_NSAP:
                data_len++;
                if (data_len != ATM_ESA_LEN) continue;
                memcpy(((struct sockaddr_atmsvc *) result)->
                  sas_addr.prv,data,ATM_ESA_LEN);
                return 0;
	    case T_ATMA:
		switch (*data++) {
		    case ATMA_AESA:
			if (data_len != ATM_ESA_LEN) continue;
			memcpy(((struct sockaddr_atmsvc *) result)->
			  sas_addr.prv,data,ATM_ESA_LEN);
			return 0;
		    case ATMA_E164:
			if (data_len > ATM_E164_LEN) continue;
			if (!found) {
			    found = data;
			    found_len = data_len;
			}
			break;
		    default:
			continue;
		}
	    case T_PTR:
		    if (dn_expand(answer,answer+answer_len,data,result,
		      res_len) < 0) return FATAL;
		    return 0;
		default:
		    continue;
	}
    }
    if (!found) return TRY_OTHER;
    memcpy(((struct sockaddr_atmsvc *) result)->sas_addr.pub,found,
      found_len);
    ((struct sockaddr_atmsvc *) result)->sas_addr.pub[found_len] = 0;
    return 0;
}


int ans_byname(const char *text,struct sockaddr_atmsvc *addr,int length,
  int flags)
{
    if (!(flags & T2A_SVC) || length != sizeof(*addr)) return TRY_OTHER; 
    memset(addr,0,sizeof(*addr));
    addr->sas_family = AF_ATMSVC;
    if (!ans(text,T_ATMA,addr,length)) return 0;
    return ans(text,T_NSAP,addr,length);
}
