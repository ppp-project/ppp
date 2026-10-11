/* text2atm.c - Converts textual representation of ATM address to binary
		encoding */

/* Written 1995-2000 by Werner Almesberger, EPFL-LRC/ICA */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>

#include "atm.h"
#include "atmres.h"


static int try_pvc(const char *text,struct sockaddr_atmpvc *addr,int flags)
{
    int part[3];
    int i;

    part[0] = part[1] = part[2] = 0;
    i = 0;
    while (1) {
	if (!*text) return FATAL; /* empty or ends with a dot */
	if (i == 3) return TRY_OTHER; /* too long */
	if (isdigit(*text)) {
	    if (*text == '0' && isdigit(text[1])) return TRY_OTHER;
		/* no leading zeroes */
	    do {
		if (part[i] > INT_MAX/10) return TRY_OTHER;/* number too big */
		part[i] = part[i]*10+*text++-'0';
	    }
	    while (isdigit(*text));
	    i++;
	    if (!*text) break;
	    if (*text++ != '.') return TRY_OTHER; /* non-PVC character */
	    continue;
	}
	if (*text == '*') {
	    if (!(flags & T2A_WILDCARD)) return FATAL; /* not allowed */
	    part[i++] = ATM_ITF_ANY; /* all *_ANY have the same value */
	}
	else {
	    if (*text != '?') return TRY_OTHER; /* invalid character */
	    if (!(flags & T2A_UNSPEC)) return FATAL; /* not allowed */
	    part[i++] = ATM_VPI_UNSPEC; /* all *_UNSPEC have the same
					   value */
	}
	if (!*++text) break;
	if (*text++ != '.') return FATAL; /* dot required */
    }
    if (i < 2) return TRY_OTHER; /* no dots */
    if (i == 2) {
	part[2] = part[1];
	part[1] = part[0];
	part[0] = 0; /* default interface */
    }
    if (part[0] > SHRT_MAX || part[2] > ATM_MAX_VCI)
	return TRY_OTHER; /* too big */
    if (part[1] > (flags & T2A_NNI ? ATM_MAX_VPI_NNI : ATM_MAX_VPI))
	return TRY_OTHER; /* too big */
    if (part[0] == ATM_VPI_UNSPEC) return FATAL; /* bad */
    addr->sap_family = AF_ATMPVC;
    addr->sap_addr.itf = part[0];
    addr->sap_addr.vpi = part[1];
    addr->sap_addr.vci = part[2];
    return 0;
}


static int search(FILE *file,const char *text,struct sockaddr *addr,int length,
  int flags)
{
    char line[MAX_ATM_NAME_LEN+1];
    const char *here;
    int result;

    while (fgets(line,MAX_ATM_NAME_LEN,file)) {
	if (!strtok(line,"\t\n ")) continue;
	while ((here = strtok(NULL,"\t\n ")))
	    if (!strcasecmp(here,text)) {
		here = strtok(line,"\t\n ");
		result = text2atm(here,addr,length,flags);
		if (result >= 0) return result;
	    }
    }
    return TRY_OTHER;
}


static int try_name(const char *text,struct sockaddr *addr,int length,
  int flags)
{
    FILE *file;
    int result;

    if (!(file = fopen(HOSTS_ATM,"r"))) return TRY_OTHER;
    result = search(file,text,addr,length,flags);
    (void) fclose(file);
    return result;
}


int text2atm(const char *text,struct sockaddr *addr,int length,int flags)
{
    int result;

    if (!*text) return -1;
    if (!(flags & (T2A_PVC | T2A_SVC))) flags |= T2A_PVC | T2A_SVC;
    if (length < sizeof(struct sockaddr_atmpvc)) return -1;
    if (flags & T2A_PVC) {
	result = try_pvc(text,(struct sockaddr_atmpvc *) addr,flags);
	if (result != TRY_OTHER) return result;
    }
    if (!(flags & T2A_NAME)) return -1;
    result = try_name(text,addr,length,flags & ~T2A_NAME);
    if (result != TRY_OTHER) return result;
    return -1;
}
