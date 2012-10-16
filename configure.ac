AC_INIT([X15], [0.1], [rbraun@sceen.net], [x15])

AC_CONFIG_SRCDIR([kern/config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign subdir-objects 1.10])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])],
         [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_PREFIX_DEFAULT([])
AC_CANONICAL_HOST
AC_PROG_CPP
AC_PROG_CC
AM_PROG_AS
AM_PROG_CC_C_O

m4_include([arch/x86/configfrag.ac])

AS_IF([test x"$arch" = x], [AC_MSG_ERROR([unsupported architecture])])
AC_SUBST([arch])

AC_ARG_ENABLE([debug],
              [AS_HELP_STRING([--disable-debug],
                              [disable the debugging facilities])])

AC_ARG_WITH([max-cpus],
            [AS_HELP_STRING([--with-max-cpus=MAX_CPUS],
                            [set the maximum number of supported processors])],
            [opt_max_cpus=$withval],
            [opt_max_cpus=32])

AC_DEFINE([__KERNEL__], [1], [kernel code])
AC_DEFINE_UNQUOTED([ARCH], [$arch], [arch])
AS_IF([test x"$enable_debug" = xno],
      [AC_DEFINE([NDEBUG], [1], [disable debugging])])
AC_DEFINE_UNQUOTED([MAX_CPUS], [$opt_max_cpus],
                   [maximum number of supported processors])

AH_BOTTOM([#include <kern/config.h>])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
