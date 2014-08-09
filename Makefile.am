ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src
EXTRA_DIST = LICENSE doxygen/dox doxygen/examples
DIST_TARGETS = dist-gzip dist-bzip2 dist-xz dist-zip

distclean-local:
	rm -rf $(top_srcdir)/autom4te.cache $(top_srcdir)/config.h.in~ $(top_srcdir)/doxygen/html \
	$(top_srcdir)/doxygen/xml $(top_srcdir)/doxygen/man $(top_srcdir)/doxygen/latex $(top_srcdir)/manual.pdf || true


doxygen: Doxyfile
	doxygen

manual.pdf: doxygen
	make -C doxygen/latex
	cp doxygen/latex/refman.pdf manual.pdf
