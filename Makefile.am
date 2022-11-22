EXTRA_DIST = COPYRIGHT LICENSE README.md
CLEANFILES =
DISTCLEANFILES =
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

USE_LCOV=@USE_LCOV@
LCOV=@LCOV@
GENHTML=@GENHTML@

clean-coverage:
	@if [ $(USE_LCOV) = yes ] ; then \
		$(LCOV) --directory . --zerocounters ; \
		echo "Removing coverage info files and generated $(abs_top_builddir)/coverage-html/ directory" ; \
		rm -rf all.coverage report.coverage ; \
		rm -rf $(abs_top_builddir)/coverage-html/ ; \
	else \
		echo "Code coverage not enabled at configuration time." ; \
		echo "Use: ./configure --with-coverage" ; \
fi

report-coverage:
	@if [ $(USE_LCOV) = yes ] ; then \
		$(LCOV) --capture --directory . --output-file all.coverage ; \
		$(LCOV) --remove all.coverage \
			$(abs_top_srcdir)/tests/\* \
			/usr/include/\* \
			--output report.coverage ; \
		$(GENHTML) --legend -o $(abs_top_builddir)/coverage-html report.coverage ; \
		echo "Generated Code Coverage report in HTML at $(abs_top_builddir)/coverage-html" ; \
	else \
		echo "Code coverage not enabled at configuration time." ; \
		echo "Use: ./configure --with-coverage" ; \
fi


LIBDNSTABLE_CURRENT=2
LIBDNSTABLE_REVISION=0
LIBDNSTABLE_AGE=2

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

TESTS = tests/tests.sh tests/test_timefilter.sh
EXTRA_DIST += \
	tests/empty-version.mtbl \
	tests/empty-version.setfile \
	tests/test-dns.mtbl \
	tests/test-dns.mtbl.old \
	tests/test-dns.setfile \
	tests/generic-tests/m1.mtbl \
	tests/generic-tests/m2.mtbl \
	tests/generic-tests/m12.mtbl \
	tests/generic-tests/test.mtbl \
	tests/test-timefilter/dns-2022-11-10.mtbl \
	tests/test-timefilter/dns-2022-11-11.mtbl \
	tests/test-timefilter/dns-2022-11-12.mtbl \
	tests/test-timefilter/dns-2022-11-13.mtbl \
	tests/test-timefilter/dns-2022-11-14.mtbl \
	tests/test-timefilter/dns-2022-11-15.mtbl \
	tests/test-timefilter/dns-2022-11-16.mtbl \
	tests/test-timefilter/dns-2022-11-17.mtbl \
	tests/test-timefilter/dns-2022-11-18.mtbl \
	tests/test-timefilter/dns-merged.mtbl \
	tests/test-timefilter/dns-test.fileset \
	tests/test-timefilter/dns-ntf-2022-11-10.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-11.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-12.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-13.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-14.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-15.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-16.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-17.mtbl \
	tests/test-timefilter/dns-ntf-2022-11-18.mtbl \
	tests/test-timefilter/dns-test-ntf.fileset \
	tests/test.subr

tests/test-dnstable_merge:
	dlname=`sed -n "s/^dlname='\(.*\)'/\1/p" dnstable/libdnstable.la` ; \
	sed -e "s;@LIBDNSTABLE_DLNAME@;$(abs_top_builddir)/dnstable/.libs/$$dlname;" ${srcdir}/src/dnstable_merge.sh.in >$@
	chmod +x $@

check_SCRIPTS = tests/test-dnstable_merge

DISTCLEANFILES += tests/test-dnstable_merge

check_PROGRAMS =

TESTS += tests/test-dnstable
check_PROGRAMS += tests/test-dnstable
tests_test_dnstable_CPPFLAGS = -DSRCDIR="\"$(abs_srcdir)\"" $(AM_CPPFLAGS)
tests_test_dnstable_LDADD = \
	dnstable/libdnstable.la \
	$(libmtbl_LIBS)
tests_test_dnstable_SOURCES = tests/test-dnstable.c tests/errors.h

check_PROGRAMS += tests/test-bitmaps
tests_test_bitmaps_CPPFLAGS = -DSRCDIR="\"$(abs_srcdir)\"" $(AM_CPPFLAGS)
tests_test_bitmaps_LDADD = \
	dnstable/entry.o \
	dnstable/triplet.o \
	dnstable/libdnstable.la \
	$(libyajl_LIBS) \
	$(libmtbl_LIBS) \
	$(libwdns_LIBS)
tests_test_bitmaps_SOURCES = tests/test-bitmaps.c

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
