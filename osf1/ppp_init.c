/*
 *  ppp_init.c --- PPP initialization/configuration for OSF/1.
 *
 * Get rid of svr4-style interface flag since the driver bits use
 * use the old calling conventions.
 *
 * Configure should return ENOTSUP instead of EINVAL
 *
 * Use sysconfigtab framework
 *
 * Defer initialization callback until later in boot, to avoid panic.
 *
 *  Note:  Checks for #ifdef CFG_OP_CONFIGURE is my cheap way of telling
 *      whether this system is V3.0+ or V2.0.  Is there a better way?  srt
 *  Note:  Checks for #ifdef CFG_PT_VM_AVAIL is my cheap way of telling
 *      whether this system is V4.0+ or earlier. smd
 */

#include <sys/sysconfig.h>
#include <sys/stream.h>

static int configured = 0;
static struct streamadm	tmpl_sa = {
    OSF_STREAMS_11,
    STR_IS_MODULE,
    { NULL },	/* sa_name, filled in at boot time */
    NULL,	/* sa_ttys */
    SQLVL_ELSEWHERE,
    "ppp"	/* "global" sync across all PPP modules */
};

extern struct streamtab ppp_ahdlcinfo;
extern struct streamtab if_pppinfo;
extern struct streamtab ppp_compinfo;
extern struct streamtab pppinfo;

#ifdef CFG_OP_CONFIGURE
/* the number of actual PPP interfaces is extended
 * on-the-fly, as needed
 */
static int nppp = 1;

cfg_subsys_attr_t ppp_attributes[] = {
    {"nppp",       CFG_ATTR_INTTYPE, 
	CFG_OP_QUERY | CFG_OP_CONFIGURE,
	(caddr_t) &nppp, 1, 1024, 0},
    {"", 0, 0, 0, 0, 0, 0} /* must be the last element */
};
#else
typedef sysconfig_op_t cfg_op_t;
#endif

/* Add the PPP streams modules to the pool of available modules.
 * If for some reason we can't add one of them, then remove the
 * ones we did succeed in adding.
 */
static int
ppp_initialize()
{
    dev_t devno = NODEV;
    int ret = ESUCCESS;

    if (!configured) {
	strcpy(tmpl_sa.sa_name, "if_ppp");
	if ((devno = strmod_add(NODEV, &if_pppinfo, &tmpl_sa)) == NODEV)
	    ret = ENODEV;

	strcpy(tmpl_sa.sa_name, "ppp_ahdl");
	if ((devno = strmod_add(NODEV, &ppp_ahdlcinfo, &tmpl_sa)) == NODEV) {
	    strcpy(tmpl_sa.sa_name, "if_ppp");
	    strmod_del(NODEV, &if_pppinfo, &tmpl_sa);
	    ret = ENODEV;
	}

	strcpy(tmpl_sa.sa_name, "pppcomp");
	if ((devno = strmod_add(NODEV, &ppp_compinfo, &tmpl_sa)) == NODEV) {
	    strcpy(tmpl_sa.sa_name, "if_ppp");
	    strmod_del(NODEV, &if_pppinfo, &tmpl_sa);
	    strcpy(tmpl_sa.sa_name, "ppp_ahdl");
	    strmod_del(NODEV, &ppp_ahdlcinfo, &tmpl_sa);
	    ret = ENODEV;
	}

	strcpy(tmpl_sa.sa_name, "ppp");
	tmpl_sa.sa_flags = STR_IS_DEVICE;
	if ((devno = strmod_add(NODEV, &pppinfo, &tmpl_sa)) == NODEV) {
	    tmpl_sa.sa_flags = STR_IS_MODULE;
	    strcpy(tmpl_sa.sa_name, "if_ppp");
	    strmod_del(NODEV, &if_pppinfo, &tmpl_sa);
	    strcpy(tmpl_sa.sa_name, "ppp_ahdl");
	    strmod_del(NODEV, &ppp_ahdlcinfo, &tmpl_sa);
	    strcpy(tmpl_sa.sa_name, "pppcomp");
	    strmod_del(NODEV, &ppp_compinfo, &tmpl_sa);
	    ret = ENODEV;
	}
	configured = 1;
    } else
	ret = EINVAL;

    return(ret);
}

#ifdef CFG_PT_VM_AVAIL
static void
ppp_callback(point, order, arg, event_arg)
int	point;
int	order;
ulong	arg;
ulong	event_arg;
{
    int ret;

    ret = ppp_initialize();

    return;		/* _callback returns void, losing info */
}
#endif /* CFG_PT_VM_AVAIL */

int
ppp_configure(op, indata, indata_size, outdata, outdata_size)
cfg_op_t  op;
char *indata, *outdata;
ulong indata_size, outdata_size;
{
    int ret = ESUCCESS;

    switch (op) {

#ifdef CFG_OP_CONFIGURE
      case CFG_OP_CONFIGURE:
#else
      case SYSCONFIG_CONFIGURE:
#endif /* CFG_OP_CONFIGURE */

#ifdef CFG_PT_VM_AVAIL
	ret = register_callback(ppp_callback, 
		CFG_PT_OLD_CONF_ALL, CFG_ORD_DONTCARE, 0L);
#else
	ret = ppp_initialize();
#endif /* CFG_PT_VM_AVAIL */

	break;

#ifdef CFG_OP_QUERY
      case CFG_OP_QUERY:
#else
      case SYSCONFIG_QUERY:
#endif
        break;

#ifdef CFG_OP_RECONFIGURE
      case CFG_OP_RECONFIGURE:
        break;
#endif

      default:
	ret = ENOTSUP;
	break;
    }

    return(ret);
}
