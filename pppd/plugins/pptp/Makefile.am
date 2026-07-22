pppd_plugin_LTLIBRARIES = pptp.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_HEADERS = pptp_callmgr.h pptp_ctrl.h pptp_msg.h pptp_options.h \
    util.h vector.h pptp_quirks.h orckit_quirks.h

pptp_la_CPPFLAGS = -I${top_srcdir}
pptp_la_LDFLAGS = -module -avoid-version
pptp_la_SOURCES = pptp.c pptp_callmgr.c pptp_ctrl.c util.c vector.c \
    pptp_quirks.c orckit_quirks.c
