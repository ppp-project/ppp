/*
 *  ppp_init.c --- PPP initialization/configuration for OSF/1.
 *
 *  Note:  Checks for #ifdef CFG_OP_CONFIGURE is my cheap way of telling
 *      whether this system is V3.0+ or V2.0.  Is there a better way?  srt
 */

#include <sys/sysconfig.h>
#include <sys/stream.h>

#ifndef PPP_VD
#include "ppp.h"
#endif

static int configured = 0;
static struct streamadm	tmpl_sa = { OSF_STREAMS_11,
    STR_IS_MODULE|STR_SYSV4_OPEN,
    NULL,
    SQLVL_MODULE,
    NULL };


extern struct streamtab ppp_asyncinfo;
extern struct streamtab ppp_ifinfo;
extern struct streamtab ppp_compinfo;

#ifdef CFG_OP_CONFIGURE
cfg_subsys_attr_t ppp_attributes[] = {
    {"", 0, 0, 0, 0, 0, 0}
};
#endif

int
ppp_configure(op, indata, indata_size, outdata, outdata_size)
cfg_op_t  op;
char *indata, *outdata;
ulong indata_size, outdata_size;
{
    dev_t devno = NODEV;
    int ret = ESUCCESS;
    int i;

    switch (op) {

#ifdef CFG_OP_CONFIGURE
      case CFG_OP_CONFIGURE:
#else
      case SYSCONFIG_CONFIGURE:
#endif
	if (!configured) {
	    strcpy(tmpl_sa.sa_name, "pppif");
	    if ((devno=strmod_add(NODEV, &ppp_ifinfo, &tmpl_sa)) == NODEV)
		return(ENODEV);

	    strcpy(tmpl_sa.sa_name, "pppasync");
	    if ((devno=strmod_add(NODEV, &ppp_asyncinfo, &tmpl_sa)) == NODEV) {
		strcpy(tmpl_sa.sa_name, "pppif");
		strmod_del(NODEV, &ppp_ifinfo, &tmpl_sa);
		return(ENODEV);
	    }

	    strcpy(tmpl_sa.sa_name, "pppcomp");
	    if ((devno = strmod_add(NODEV, &ppp_compinfo, &tmpl_sa)) == NODEV) {
		strcpy(tmpl_sa.sa_name, "pppif");
		strmod_del(NODEV, &ppp_ifinfo, &tmpl_sa);
		strcpy(tmpl_sa.sa_name, "pppasync");
		strmod_del(NODEV, &ppp_asyncinfo, &tmpl_sa);
		return(ENODEV);
	    }

	    ppp_attach();

	    configured = 1;
	} else
	    ret = EINVAL;
	break;

      default:
	ret = EINVAL;
	break;
    }

    return(ret);
}
                                   


