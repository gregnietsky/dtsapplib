#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([dtsapplib],[0.2],[gregory@distrotech.co.za])
AC_CONFIG_SRCDIR([src/thread.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_C_INLINE
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_HEADER_RESOLV
AC_TYPE_SSIZE_T

# Checks for libraries.
#APP LIB changes
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
LT_INIT()
AM_PROG_CC_C_O

AC_CHECK_LIB([pthread], [pthread_create])

AC_ARG_ENABLE([dev-mode], AS_HELP_STRING([--enable-dev-mode], [Developer mode -g -Wall -Werror -pedantic-errors]))
AC_ARG_ENABLE([world-peace], AS_HELP_STRING([--enable-world-peace], [Yeah right .....]))

AC_CHECK_LIB([z], [compress])

PKG_CHECK_MODULES(LIBNFQUEUE, libnetfilter_queue >= 0, [have_libnfqueue=yes], [have_libnfqueue=no])
AS_IF([test "x$have_libnfqueue" = "xyes"],
	[AC_CHECK_LIB([netfilter_queue], [nfq_open])])

PKG_CHECK_MODULES(LIBNFCT, libnetfilter_conntrack >= 0, [have_libnfctrack=yes], [have_libnfctrack=no])
AS_IF([test "x$have_libnfctrack" = "xyes"],
	[AC_CHECK_LIB([netfilter_conntrack], [nfct_open])])

if (test "x$ac_cv_lib_framework_framework_mkthread" = "xyes") && (test "$have_libframework" = "xyes") ; then
   FRAMEWORK_INCL="$LIBFRAMEWORK_CFLAGS"
  else
   FRAMEWORK_INCL="-I\$(srcdir)/src/include"
   FRAMEWORK_LIBS="../src/libframework.la"
fi;

if test "x$enable_dev_mode" = "xyes" ; then
 DEVELOPER_CFLAGS="-g -Wall -Werror -pedantic-errors"
fi;

AC_CHECK_LIB([m], [pow], [], [AC_MSG_ERROR([Requires Math Lib -lm])])
AC_CHECK_LIB([lber], [ber_free], [LDAP_LIBS="-llber"], [AC_MSG_ERROR([Requires LDAP/BER/SASL Lib -llber -lldap -lsasl2])])
AC_CHECK_LIB([sasl2], [sasl_client_init], [LDAP_LIBS="${LDAP_LIBS} -lsasl2"], [AC_MSG_ERROR([Requires LDAP/BER/SASL Lib -llber -lldap -lsasl2])])
AC_CHECK_LIB([ldap], [ldap_initialize], [LDAP_LIBS="${LDAP_LIBS} -lldap"], [AC_MSG_ERROR([Requires LDAP/BER/SASL Lib -llber -lldap -lsasl2])])
AC_SUBST(LDAP_LIBS)
PKG_CHECK_MODULES(XML, libxml-2.0 >= 2.9)
PKG_CHECK_MODULES(XSLT, libxslt >= 1.1)

AC_SUBST(FRAMEWORK_LIBS)
AC_SUBST(FRAMEWORK_INCL)
AC_SUBST(FRAMEWORK_SOURCES)
AC_SUBST(DEVELOPER_CFLAGS)

AM_CONDITIONAL([FRAMEWORK_INSTALL], [test "x$enable_framework_install" = xyes])
AM_CONDITIONAL([FRAMEWORK_SYSTEM], [test "x$ac_cv_lib_framework_framework_mkthread" != "xyes"])

LIBCURL_CHECK_CONFIG

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h unistd.h syslog.h sys/time.h netdb.h arpa/inet.h])

AC_CHECK_FUNCS([gethostbyaddr])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([strtoull])

AC_CHECK_LIB([ssl], [SSL_new])
AC_CHECK_LIB([crypto], [SHA512_Init])
AC_CHECK_LIB([uuid], [uuid_generate])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_PROG_RANLIB
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap select socket])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/libnetlink/Makefile
                 src/libdtsapp.pc])
AC_OUTPUT
