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

AC_ARG_ENABLE([test-module],
              [AS_HELP_STRING([--enable-test-module=TEST_MODULE],
                              [run the given test module instead of booting])],
              [enable_test_module=$enableval],
              [enable_test_module=no])

AC_ARG_WITH([max-cpus],
            [AS_HELP_STRING([--with-max-cpus=MAX_CPUS],
                            [set the maximum number of supported processors])],
            [opt_max_cpus=$withval],
            [opt_max_cpus=32])

AC_DEFINE([__KERNEL__], [1], [kernel code])
AC_DEFINE_UNQUOTED([ARCH], [$arch], [arch])

AS_IF([test x"$enable_debug" = xno],
      [AC_DEFINE([NDEBUG], [1], [disable debugging])])

m4_define([ENABLE_TEST_MODULE],
          [AS_CASE(["$enable_test_module"],
                   [llsync_defer], [test_llsync_defer=yes],
                   [pmap_update_mp], [test_pmap_update_mp=yes],
                   [x86_pmap_remove_ptp],
                       [test_x86_pmap_remove_ptp=yes
                        AC_MSG_NOTICE([forcing max_cpus to 1])
                        opt_max_cpus=1],
                   [AC_MSG_ERROR([invalid test module])])
          AC_DEFINE([RUN_TEST_MODULE], [1],
                    [run test module instead of booting])
          AC_MSG_NOTICE([test module enabled: $enable_test_module])])

AS_IF([test x"$enable_test_module" != xno], [ENABLE_TEST_MODULE])
AM_CONDITIONAL([TEST_LLSYNC_DEFER],
               [test x"$test_llsync_defer" = xyes])
AM_CONDITIONAL([TEST_PMAP_UPDATE_MP],
               [test x"$test_pmap_update_mp" = xyes])
AM_CONDITIONAL([TEST_X86_PMAP_REMOVE_PTP],
               [test x"$test_x86_pmap_remove_ptp" = xyes])

AC_DEFINE_UNQUOTED([MAX_CPUS], [$opt_max_cpus],
                   [maximum number of supported processors])
AC_MSG_NOTICE([maximum number of supported processors: $opt_max_cpus])

AH_BOTTOM([#include <kern/config.h>])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
