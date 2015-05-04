AC_INIT(mod_auth_xradius, 0.4.6)
OOO_CONFIG_NICE(config.nice)
MOD_AUTH_XRADIUS_VERSION=AC_PACKAGE_VERSION
AC_PREREQ(2.53)
AC_CONFIG_SRCDIR([src/mod_auth_xradius.c])
AC_CONFIG_AUX_DIR(config)
OOO_MAINTAIN_MODE
AM_MAINTAINER_MODE
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AM_CONFIG_HEADER(include/mod_auth_xradius_config.h:config.in)

AC_SUBST(MOD_AUTH_XRADIUS_VERSION)

AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL
AC_PROG_RANLIB

AP_VERSION=2.0.40
CHECK_APACHE(,$AP_VERSION,
    :,:,
    AC_MSG_ERROR([*** Apache version $AP_VERSION not found!])
)

LIBTOOL="`${APR_CONFIG} --apr-libtool`"
AC_SUBST(LIBTOOL)

have_apr_memcache=0
CHECK_APR_MEMCACHE([have_apr_memcache=1], [have_apr_memcache=0])
AC_SUBST(have_apr_memcache)

LIBRADIUS_CFLAGS="-I\$(top_srcdir)/libradius"
MODULE_CFLAGS="${LIBRADIUS_CFLAGS} ${APR_MEMCACHE_CFLAGS} ${APXS_CFLAGS} ${AP_INCLUDES} ${APR_INCLUDES} ${APU_INCLUDES}"
MODULE_LIBS="${APR_MEMCACHE_LIBS}"

AC_SUBST(MODULE_CFLAGS)
AC_SUBST(MODULE_LIBS)

AC_CONFIG_FILES([Makefile include/mod_auth_xradius.h])
AC_OUTPUT

echo "---"
echo "Configuration summary for mod_auth_xradius:"
echo ""
echo "   * mod_auth_xradius version:	${MOD_AUTH_XRADIUS_VERSION}"
echo "   * Apache Modules directory:	${AP_LIBEXECDIR}"
echo ""
echo "---"
