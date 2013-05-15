ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I./include $(DEVELOPER_CFLAGS)
EXTRA_DIST = include
SUBDIRS = libnetlink
       
lib_LTLIBRARIES = libdtsapp.la
includeinstdir = $(oldincludedir)/dtsapplib
includeinst_DATA = include/dtsapp.h

libdtsapp_la_SOURCES = refobj.c lookup3.c thread.c main.c unixsock.c util.c radius.c socket.c sslutil.c interface.c config.c \
                          iputil.c nf_queue.c nf_ctrack.c zlib.c rfc6296.c libxml2.c libxslt.c openldap.c

libdtsapp_la_LIBADD = ./libnetlink/libnetlink.la $(XSLT_LIBS) $(XML_LIBS) $(LDAP_LIBS) $(LIBS)
libdtsapp_la_CFLAGS = -I./include -I./libnetlink/include $(DEVELOPER_CFLAGS) $(XSLT_CFLAGS) $(XML_CFLAGS)
libdtsapp_la_LDFLAGS = -version-info 1:0:1

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdtsapp.pc
