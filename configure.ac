AC_PREREQ(2.64)
AC_INIT([dnstable],
        [0.13.0],
        [https://github.com/farsightsec/dnstable/issues],
        [dnstable],
        [https://github.com/farsightsec/dnstable])
AC_CONFIG_SRCDIR([dnstable/dnstable.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects color-tests])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

my_CFLAGS="-Wall \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wpointer-arith \
-Wpointer-arith -Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile dnstable/libdnstable.pc])
AC_CONFIG_FILES([tests/tests.sh], [chmod +x tests/tests.sh])
AC_CONFIG_FILES([tests/test_timefilter.sh], [chmod +x tests/test_timefilter.sh])

PKG_PROG_PKG_CONFIG
if test -n "$PKG_CONFIG"; then
    # Horrible hack for systems where the pkg-config install directory is simply wrong!
    if $PKG_CONFIG --variable=pc_path pkg-config 2>/dev/null | grep -q /libdata/; then
        PKG_INSTALLDIR(['${prefix}/libdata/pkgconfig'])
    else
        PKG_INSTALLDIR
    fi
else
    AC_MSG_ERROR([pkg-config is required!])
fi

AC_SEARCH_LIBS([clock_gettime], [rt])
AC_CHECK_FUNCS([clock_gettime])

AC_CHECK_HEADERS([sys/endian.h endian.h])

PKG_CHECK_MODULES([libmtbl], [libmtbl >= 1.5.0])
PKG_CHECK_MODULES([libwdns], [libwdns >= 0.11.0])
PKG_CHECK_MODULES([libyajl], [yajl >= 2], [], [MY_CHECK_YAJL_1])

AX_PTHREAD([
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"
])

AC_PATH_PROG([ASCIIDOC], [a2x])
AM_CONDITIONAL([BUILD_MAN], [test -n "$ASCIIDOC"])
if test -n "$ASCIIDOC"; then
    DOC_MAN_MSG="yes (asciidoc available)"
else
    DOC_MAN_MSG="no (asciidoc not available)"
fi

gl_LD_VERSION_SCRIPT

AC_ARG_WITH(coverage,
[ --with-coverage[=PROGRAM] enable test and coverage target using the specified lcov], lcov="$withval", lcov="no")

USE_LCOV="no"
if test "$lcov" != "no"; then
	if test "$lcov" != "yes"; then
		LCOV=$lcov
	else
		AC_PATH_PROG([LCOV], [lcov])
	fi
	if test -x "${LCOV}"; then
		USE_LCOV="yes"
	else
		AC_MSG_ERROR([Cannot find lcov.])
	fi
	# is genhtml always in the same directory?
	GENHTML=`echo "$LCOV" | ${SED} s/lcov$/genhtml/`
	if test ! -x $GENHTML; then
		AC_MSG_ERROR([genhtml not found, needed for lcov])
	fi
	CFLAGS="$CFLAGS --coverage"
	AC_CHECK_LIB(gcov, gcov_exit, [ LIBS="$LIBS -lgcov" ])
	AC_SUBST(CPPFLAGS)
	AC_SUBST(LIBS)
	AC_SUBST(LCOV)
	AC_SUBST(GENHTML)
fi
AC_SUBST(USE_LCOV)

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
        pkgconfigdir:           ${pkgconfigdir}

        building manpage docs:  ${DOC_MAN_MSG}
        code coverage enabled:  ${USE_LCOV}
])
