EXTRA_DIST = COPYRIGHT LICENSE README.md
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I${top_srcdir}/dnstable

AM_CFLAGS = \
	${my_CFLAGS} \
	$(libmtbl_CFLAGS) \
	$(libwdns_CFLAGS) \
	$(libyajl_CFLAGS)

AM_LDFLAGS =

LIBDNSTABLE_CURRENT=1
LIBDNSTABLE_REVISION=0
LIBDNSTABLE_AGE=1

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
	libmy/ip_arith.h \
	libmy/hex_decode.h \
	libmy/my_alloc.h \
	libmy/my_time.h \
	libmy/print_string.h \
	libmy/vector.h \
	libmy/ubuf.h \
	libmy/my_byteorder.h

dnstable_libdnstable_la_LIBADD = \
	$(libmtbl_LIBS) \
	$(libwdns_LIBS) \
	$(libyajl_LIBS)
dnstable_libdnstable_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBDNSTABLE_CURRENT):$(LIBDNSTABLE_REVISION):$(LIBDNSTABLE_AGE)
if HAVE_LD_VERSION_SCRIPT
dnstable_libdnstable_la_LDFLAGS += \
	-Wl,--version-script=$(top_srcdir)/dnstable/libdnstable.sym
else
dnstable_libdnstable_la_LDFLAGS += \
	-export-symbols-regex "^(dnstable_[a-z].*)"
endif
EXTRA_DIST += dnstable/libdnstable.sym

EXTRA_DIST += src/dnstable_merge.sh.in
bin_SCRIPTS = src/dnstable_merge
CLEANFILES += $(bin_SCRIPTS)
src/dnstable_merge:
	dlname=`sed -n "s/^dlname='\(.*\)'/\1/p" dnstable/libdnstable.la` ; \
	sed -e "s/@LIBDNSTABLE_DLNAME@/$$dlname/" ${srcdir}/src/dnstable_merge.sh.in >$@
	chmod +x $@

pkgconfig_DATA = dnstable/libdnstable.pc
EXTRA_DIST += dnstable/libdnstable.pc.in
CLEANFILES += dnstable/libdnstable.pc

bin_PROGRAMS = src/dnstable_dump
src_dnstable_dump_SOURCES = \
	libmy/argv.c \
	libmy/argv.h \
	libmy/argv_loc.h \
	src/dnstable_dump.c
src_dnstable_dump_LDADD = \
	dnstable/libdnstable.la \
	$(libmtbl_LIBS) \
	$(libwdns_LIBS)

bin_PROGRAMS += src/dnstable_lookup
src_dnstable_lookup_SOURCES = src/dnstable_lookup.c
src_dnstable_lookup_LDADD = \
	dnstable/libdnstable.la \
	$(libmtbl_LIBS) \
	$(libwdns_LIBS)

TESTS = tests/tests.sh
EXTRA_DIST += tests/test-dns.mtbl
EXTRA_DIST += tests/test-dns.setfile

check_PROGRAMS =

if BUILD_MAN
SUFFIXES = .1.txt .3.txt .5.txt .7.txt .1 .3 .5 .7

ASCIIDOC_PROCESS = $(AM_V_GEN) $(ASCIIDOC) -f manpage --no-xmllint --asciidoc-opt="-f man/asciidoc.conf" $<

.1.txt.1:
	$(ASCIIDOC_PROCESS)

.3.txt.3:
	$(ASCIIDOC_PROCESS)

.5.txt.5:
	$(ASCIIDOC_PROCESS)

.7.txt.7:
	$(ASCIIDOC_PROCESS)

endif

dist_man_MANS = \
	man/dnstable-encoding.5 \
	man/dnstable_dump.1 \
	man/dnstable_lookup.1 \
	man/dnstable_merge.1 \
	man/dnstable_entry.3 \
	man/dnstable_iter.3 \
	man/dnstable_query.3 \
	man/dnstable_reader.3 \
	man/dnstable_merge_func.3 \
	man/dnstable.7

EXTRA_DIST += \
	man/dnstable-encoding.5.txt \
	man/dnstable_dump.1.txt \
	man/dnstable_lookup.1.txt \
	man/dnstable_merge.1.txt \
	man/dnstable_entry.3.txt \
	man/dnstable_iter.3.txt \
	man/dnstable_query.3.txt \
	man/dnstable_reader.3.txt \
	man/dnstable_merge_func.3.txt \
	man/dnstable.7.txt
