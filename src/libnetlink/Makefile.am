ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I$(srcdir)/include $(DEVELOPER_CFLAGS)
EXTRA_DIST = include libnetlink.h ipx_pton.c

noinst_LTLIBRARIES = libnetlink.la

libnetlink_la_SOURCES = libnetlink.c utils.c rt_names.c ll_types.c ll_proto.c ll_addr.c inet_proto.c \
			ipx_ntop.c dnet_ntop.c dnet_pton.c ll_map.c
libnetlink_la_CFLAGS = -I$(srcdir)/include

includeinstdir = $(oldincludedir)/dtsapplib
includeinst_DATA = include/libnetlink.h include/utils.h include/ll_map.h include/rtm_map.h
