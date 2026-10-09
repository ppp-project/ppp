pppd_plugin_LTLIBRARIES = pppoatm.la
pppd_plugindir = $(PPPD_PLUGIN_DIR)

noinst_HEADERS = \
    atm.h \
    atmres.h \
    atmsap.h

pppoatm_la_CPPFLAGS = -I${top_srcdir}
pppoatm_la_LDFLAGS = -module -avoid-version
pppoatm_la_SOURCES = pppoatm.c text2qos.c text2atm.c misc.c
