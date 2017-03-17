AC_INIT([X15], [0.1], [rbraun@sceen.net], [x15])

AC_CONFIG_SRCDIR([kern/config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([tools/m4])

AM_INIT_AUTOMAKE([foreign subdir-objects 1.11])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])],
         [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_PREFIX_DEFAULT([])
AC_CANONICAL_HOST
AC_PROG_CPP
AC_PROG_CC
AM_PROG_AS
AM_PROG_CC_C_O

# Disable PIE if enabled by default
AX_APPEND_COMPILE_FLAGS([-no-pie -fno-pie])

AC_HEADER_ASSERT()

m4_include([arch/x86/configfrag.ac])

AS_IF([test x"$arch" = x], [AC_MSG_ERROR([unsupported architecture])])
AC_SUBST([arch])

AC_ARG_ENABLE([test-module],
              [AS_HELP_STRING([--enable-test-module=TEST_MODULE],
                              [run the given test module instead of booting])],
              [enable_test_module=$enableval],
              [enable_test_module=no])

AC_ARG_WITH([max-cpus],
            [AS_HELP_STRING([--with-max-cpus=MAX_CPUS],
                            [set the maximum number of supported processors])],
            [opt_max_cpus=$withval],
            [opt_max_cpus=128])

AC_ARG_ENABLE([mutex-pi],
              [AS_HELP_STRING([--enable-mutex-pi],
                              [enable priority inheritance for regular mutexes
                               (note that priority inheritance is always
                                enabled for real-time mutexes)])])

AC_ARG_ENABLE([thread-stack-guard],
              [AS_HELP_STRING([--enable-thread-stack-guard],
                              [enable the use of guard pages around a thread
                               stack to catch potential overflows (note that
                               this feature wastes expensive virtual memory
                               and has some overhead during thread creation
                               and destruction)])])

AC_DEFINE([__KERNEL__], [1], [kernel code])
AC_DEFINE_UNQUOTED([X15_ARCH], [$arch], [arch])

m4_define([ENABLE_TEST_MODULE],
          [AS_CASE(["$enable_test_module"],
                   [llsync_defer], [test_llsync_defer=yes],
                   [mutex_pi], [test_mutex_pi=yes],
                   [pmap_update_mp], [test_pmap_update_mp=yes],
                   [sref_dirty_zeroes], [test_sref_dirty_zeroes=yes],
                   [sref_noref], [test_sref_noref=yes],
                   [sref_weakref], [test_sref_weakref=yes],
                   [vm_page_fill], [test_vm_page_fill=yes],
                   [x86_double_fault], [test_x86_double_fault=yes],
                   [xcall], [test_xcall=yes],
                   [AC_MSG_ERROR([invalid test module])])
          AC_DEFINE([X15_RUN_TEST_MODULE], [1],
                    [run test module instead of booting])
          AC_MSG_NOTICE([test module enabled: $enable_test_module])])

AS_IF([test x"$enable_test_module" != xno], [ENABLE_TEST_MODULE])
AM_CONDITIONAL([TEST_LLSYNC_DEFER],
               [test x"$test_llsync_defer" = xyes])
AM_CONDITIONAL([TEST_MUTEX_PI],
               [test x"$test_mutex_pi" = xyes])
AM_CONDITIONAL([TEST_PMAP_UPDATE_MP],
               [test x"$test_pmap_update_mp" = xyes])
AM_CONDITIONAL([TEST_SREF_DIRTY_ZEROES],
               [test x"$test_sref_dirty_zeroes" = xyes])
AM_CONDITIONAL([TEST_SREF_NOREF],
               [test x"$test_sref_noref" = xyes])
AM_CONDITIONAL([TEST_SREF_WEAKREF],
               [test x"$test_sref_weakref" = xyes])
AM_CONDITIONAL([TEST_VM_PAGE_FILL],
               [test x"$test_vm_page_fill" = xyes])
AM_CONDITIONAL([TEST_X86_DOUBLE_FAULT],
               [test x"$test_x86_double_fault" = xyes])
AM_CONDITIONAL([TEST_XCALL],
               [test x"$test_xcall" = xyes])

AC_DEFINE_UNQUOTED([X15_MAX_CPUS], [$opt_max_cpus],
                   [maximum number of supported processors])
AC_MSG_NOTICE([maximum number of supported processors: $opt_max_cpus])

AS_IF([test x"$enable_mutex_pi" = xyes],
      [AC_DEFINE_UNQUOTED([X15_MUTEX_PI], [],
                          [Enable priority inheritance for regular mutexes])])

AS_IF([test x"$enable_thread_stack_guard" = xyes],
      [AC_DEFINE_UNQUOTED([X15_THREAD_STACK_GUARD], [],
                          [Enable the use of guard pages for thread stacks])])

AH_BOTTOM([#include <kern/config.h>])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
