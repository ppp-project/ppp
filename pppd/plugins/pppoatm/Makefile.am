pppd_plugin_LTLIBRARIES = pppoatm.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_HEADERS = \
    atm.h \
    atmres.h \
    atmsap.h

pppoatm_la_CPPFLAGS = -I${top_srcdir}
pppoatm_la_LDFLAGS = -module -avoid-version
pppoatm_la_SOURCES = pppoatm.c

if WITH_LIBATM
pppoatm_la_LIBADD = -latm
else
pppoatm_la_SOURCES += text2qos.c text2atm.c misc.c ans.c
pppoatm_la_LIBADD = -lresolv
endif
