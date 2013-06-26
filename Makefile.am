INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall	$(COVERAGE_CFLAGS)			\
  	$(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) $(LIBSMPP34_CFLAGS)

AM_LDFLAGS = $(COVERAGE_LDFLAGS)

lib_LTLIBRARIES = libchan_openbsc.la

libchan_openbsc_la_SOURCES = channel.c bsc.c config.c mncc.c
libchan_openbsc_la_LIBADD = \
		$(top_builddir)/src/libmsc/libmsc.la \
		$(top_builddir)/src/libbsc/libbsc.la \
		$(top_builddir)/src/libtrau/libtrau.la \
		$(top_builddir)/src/libctrl/libctrl.la \
		$(top_builddir)/src/libcommon/libcommon.la \
		-ldbi -ldl $(LIBCRYPT) 					   \
		$(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMOCORE_LIBS)  \
		$(LIBOSMOABIS_LIBS) $(LIBSMPP34_LIBS)
