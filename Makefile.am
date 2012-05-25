EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I${top_srcdir}/dnstable

AM_CFLAGS = \
	${my_CFLAGS} \
	$(libjansson_CFLAGS) \
	$(libmtbl_CFLAGS) \
	$(libnmsg_CFLAGS) \
	$(libwdns_CFLAGS)

AM_LDFLAGS = -Wl,--as-needed

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@exec_prefix\@,$(exec_prefix),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@includedir\@,$(includedir),g' \
	< $< > $@ || rm $@

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

LIBDNSTABLE_CURRENT=0
LIBDNSTABLE_REVISION=0
LIBDNSTABLE_AGE=0

include_HEADERS = dnstable/dnstable.h
lib_LTLIBRARIES = dnstable/libdnstable.la

dnstable_libdnstable_la_SOURCES = \
	dnstable/dnstable.h \
	dnstable/dnstable-private.h \
	dnstable/entry.c \
	dnstable/iter.c \
	dnstable/merge.c \
	dnstable/query.c \
	dnstable/reader.c \
	dnstable/triplet.c \
	librsf/ip_arith.h \
	librsf/hex_decode.h \
	librsf/my_alloc.h \
	librsf/print_string.h \
	librsf/vector.h \
	librsf/ubuf.h

dnstable_libdnstable_la_LIBADD = \
	$(libjansson_LIBS) \
	$(libmtbl_LIBS) \
	$(libwdns_LIBS)
dnstable_libdnstable_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBDNSTABLE_CURRENT):$(LIBDNSTABLE_REVISION):$(LIBDNSTABLE_AGE) \
	-export-symbols-regex "^(dnstable_[a-z].*)"

install-exec-hook: src/dnstable_merge
	rm -f $(DESTDIR)$(libdir)/libdnstable.la
	install -m 0755 ${top_srcdir}/src/dnstable_merge $(DESTDIR)$(bindir)/dnstable_merge

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dnstable/libdnstable.pc
EXTRA_DIST += dnstable/libdnstable.pc.in
CLEANFILES += dnstable/libdnstable.pc

EXTRA_DIST += src/dnstable_merge

bin_PROGRAMS = src/dnstable_convert
src_dnstable_convert_SOURCES = src/dnstable_convert.c
src_dnstable_convert_LDADD = \
	dnstable/libdnstable.la \
	$(libmtbl_LIBS) \
	$(libnmsg_LIBS) \
	$(libwdns_LIBS)

bin_PROGRAMS += src/dnstable_dump
src_dnstable_dump_SOURCES = \
	librsf/argv.c \
	librsf/argv.h \
	librsf/argv_loc.h \
	src/dnstable_dump.c
src_dnstable_dump_LDADD = \
	dnstable/libdnstable.la \
	$(libwdns_LIBS)

bin_PROGRAMS += src/dnstable_lookup
src_dnstable_lookup_SOURCES = src/dnstable_lookup.c
src_dnstable_lookup_LDADD = \
	dnstable/libdnstable.la \
	$(libwdns_LIBS)

TESTS =

check_PROGRAMS =

SUFFIXES = .1.txt .3.txt .5.txt .7.txt .1 .3 .5 .7

ASCIIDOC_PROCESS = a2x -f manpage --asciidoc-opt="-f man/asciidoc.conf" $<

.1.txt.1:
	$(ASCIIDOC_PROCESS)

.3.txt.3:
	$(ASCIIDOC_PROCESS)

.5.txt.5:
	$(ASCIIDOC_PROCESS)

.7.txt.7:
	$(ASCIIDOC_PROCESS)

dist_man_MANS = \
	man/dnstable-encoding.5

EXTRA_DIST += \
	man/dnstable-encoding.5.txt
