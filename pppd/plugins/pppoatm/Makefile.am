pppd_plugin_LTLIBRARIES = pppoatm.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_HEADERS = \
    libatm/atm.h \
    atmres.h \
    atmsap.h

pppoatm_la_CPPFLAGS = -I${top_srcdir}
pppoatm_la_LDFLAGS = -module -avoid-version
pppoatm_la_SOURCES = pppoatm.c

if WITH_EXTERNAL_LIBATM
pppoatm_la_LIBADD = -latm
else
pppoatm_la_CPPFLAGS += -I${srcdir}/libatm
pppoatm_la_SOURCES += libatm/text2qos.c libatm/text2atm.c libatm/misc.c
endif
