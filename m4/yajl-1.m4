AC_DEFUN([MY_CHECK_YAJL_1], [
  save_CFLAGS="$CFLAGS"
  save_LIBS="$LIBS"

  libyajl_CFLAGS=""
  libyajl_LIBS=""

  AC_CHECK_HEADER(
    [yajl/yajl_gen.h],
    [],
    [AC_MSG_ERROR([required header file yajl/yajl_gen.h not found])]
  )

  AC_CHECK_LIB(
    [yajl],
    [yajl_gen_alloc2],
    [
      libyajl_LIBS="-lyajl"
      AC_DEFINE([HAVE_YAJL_1], [1], [Define to 1 if YAJL is version 1.])
    ],
    [AC_MSG_ERROR([yajl >= 1.0.8 not found])]
  )

  CFLAGS="$save_CFLAGS"
  LIBS="$save_LIBS"

  AC_SUBST([libyajl_CFLAGS])
  AC_SUBST([libyajl_LIBS])
])
