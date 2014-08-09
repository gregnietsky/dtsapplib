ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I$(srcdir)/include $(DEVELOPER_CFLAGS)
EXTRA_DIST = include
if LINUXSYSTEM
  NLSUBDIR = libnetlink
  SYSSOURCE = unixsock.c nf_queue.c nf_ctrack.c radius.c interface.c iputil.c rfc6296.c
  SYSLIBS = ./libnetlink/libnetlink.la
endif

if WIN32SYSTEM
  SYSSOURCE = winiface.cpp
  SYSLIBS = -liphlpapi -lws2_32 
  SYSLDFLAGS = -no-undefined
endif

SUBDIRS = $(NLSUBDIR)

lib_LTLIBRARIES = libdtsapp.la
includeinstdir = $(includedir)/dtsapplib
includeinst_DATA = include/dtsapp.h

libdtsapp_la_SOURCES = refobj.c lookup3.c thread.c main.c util.c socket.c sslutil.c config.c \
                       zlib.c libxml2.c libxslt.c openldap.c curl.c $(SYSSOURCE) fileutil.c

libdtsapp_la_LIBADD = $(SYSLIBS) $(XSLT_LIBS) $(XML_LIBS) $(LDAP_LIBS) $(LIBS) $(LIBCURL)
libdtsapp_la_CFLAGS = $(AM_CFLAGS) -I./libnetlink/include $(DEVELOPER_CFLAGS) $(XSLT_CFLAGS) $(XML_CFLAGS) $(LIBCURL_CPPFLAGS)
libdtsapp_la_LDFLAGS = -version-info $(LT_LIBVER) -release $(VERSION) $(SYSLDFLAGS)

# Here are a set of rules to help you update your library version information:
#
#    Start with version information of `0:0:0' for each libtool library.
#    Update the version information only immediately before a public release of your software.
#    More frequent updates are unnecessary, and only guarantee that the current interface number gets larger faster.
#    If the library source code has changed at all since the last update, then increment revision (`c:r:a' becomes `c:r+1:a').
#    If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
#    If any interfaces have been added since the last public release, then increment age.
#    If any interfaces have been removed since the last public release, then set age to 0. 


pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdtsapp.pc
