AUTOMAKE_OPTIONS = foreign dist-bzip2

LIBRADIUS_EXTRA = libradius/md5.h libradius/radlib.h \
                libradius/radlib_vs.h libradius/porting.h \
                libradius/radlib_private.h \
                libradius/README libradius/libradius.3 \
                libradius/radius.conf.5

EXTRA_DIST = m4/outoforder.m4 m4/apache.m4 \
		m4/apr_memcache.m4 \
		m4/apache_test.m4 \
		include/mod_auth_xradius.h.in \
		README \
		NOTICE LICENSE autogen.sh \
                ${LIBRADIUS_EXTRA}

mod_auth_xradius_la_SOURCES = src/mod_auth_xradius.c src/xradius_cache.c
mod_auth_xradius_la_CFLAGS = -Wall ${MODULE_CFLAGS}
mod_auth_xradius_la_LDFLAGS = -rpath ${AP_LIBEXECDIR} -module -avoid-version ${MODULE_LIBS}
mod_auth_xradius_la_LIBADD = libradius.la

apachemod_LTLIBRARIES = mod_auth_xradius.la
apachemoddir=${AP_LIBEXECDIR}

noinst_LTLIBRARIES = libradius.la
libradius_la_SOURCES = libradius/radlib.c libradius/md5c.c
libradius_la_CFLAGS = ${MODULE_CFLAGS}
libradius_la_LDFLAGS = ${MODULE_LIBS}

install: install-am
	rm -f $(DESTDIR)${AP_LIBEXECDIR}/mod_auth_xradius.a
	rm -f $(DESTDIR)${AP_LIBEXECDIR}/mod_auth_xradius.la
	@echo ""
	@echo "***********************************************"
	@echo ""
	@echo "   Please read the documentation at    "
	@echo "   http://www.outoforder.cc/ for   "
	@echo "   details on configuration of this module     "
	@echo ""
	@echo "***********************************************"
	@echo ""		
