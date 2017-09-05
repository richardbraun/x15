AC_PREREQ([2.69])
AC_INIT([X15], [0.1], [rbraun@sceen.net], [x15])

AC_CONFIG_SRCDIR([kern/config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([tools/m4])

# Artificially create the doc subdirectory since Automake apparently
# won't do it itself.
AC_CONFIG_COMMANDS([doc/.empty])

AM_INIT_AUTOMAKE([foreign subdir-objects 1.13])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])],
         [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_CANONICAL_HOST
AC_PROG_CPP
AC_PROG_CC
AM_PROG_AS
AM_PROG_CC_C_O

AX_PROG_ASCIIDOC([AC_MSG_NOTICE([asciidoc not found, not building html documentation])])
AX_PROG_HIGHLIGHT([AS_IF([test x"$ASCIIDOC" != x],
                         [AC_MSG_NOTICE([highlight not found, not building html documentation])])])
AX_PROG_A2X([AC_MSG_NOTICE([a2x not found, not building man pages])])

# Disable PIE if enabled by default
AX_APPEND_COMPILE_FLAGS([-no-pie -fno-pie])

AC_HEADER_ASSERT()

# --enable options

AC_ARG_ENABLE([64bits],
              [AS_HELP_STRING([--enable-64bits],
                              [build for a 64-bits target processor])],
              [],
              [enable_64bits=default])

AC_ARG_ENABLE([shell],
              [AS_HELP_STRING([--enable-shell],
                              [enable the diagnostics shell])],
              [],
              [enable_shell=no])

AC_ARG_ENABLE([test-module],
              [AS_HELP_STRING([--enable-test-module=TEST_MODULE],
                              [run the given test module instead of booting])],
              [enable_test_module=$enableval],
              [enable_test_module=])

AC_ARG_ENABLE([thread-stack-guard],
              [AS_HELP_STRING([--enable-thread-stack-guard],
                              [enable kernel thread stack guard pages])],
              [],
              [enable_thread_stack_guard=no])

# --with options

AC_ARG_WITH([clock-freq],
            [AS_HELP_STRING([--with-clock-freq=CLOCK_FREQ],
                            [set the low resolution clock frequency (100-1000 Hz)])],
            [opt_clock_freq=$withval],
            [opt_clock_freq=200])

AC_ARG_WITH([max-cpus],
            [AS_HELP_STRING([--with-max-cpus=MAX_CPUS],
                            [set the maximum number of supported processors])],
            [opt_max_cpus=$withval],
            [opt_max_cpus=128])

AC_ARG_WITH([mutex-impl],
            [AS_HELP_STRING([--with-mutex-impl=MUTEX_IMPL],
                            [select the mutex implementation (adaptive, pi, or plain)])],
            [opt_mutex_impl=$withval],
            [opt_mutex_impl=plain])

# 32/64-bits processor selection

AS_IF([test -z "$enable_64bits"], [enable_64bits=yes],
      [test x"$enable_64bits" = x"default"], [enable_64bits=],
      [test x"$enable_64bits" != xyes -a x"$enable_64bits" != xno],
      [AC_MSG_ERROR([target processor must be either 32-bits or 64-bits])])

# Architecture-specific configuration

m4_include([arch/x86/configfrag.ac])

AS_IF([test x"$arch" = x], [AC_MSG_ERROR([unsupported architecture])])
AC_SUBST([arch])

# Shell selection

AS_IF([test x"$enable_shell" = xyes],
      [AC_DEFINE_UNQUOTED([X15_ENABLE_SHELL], [],
                          [Enable the diagnostics shell])])
AM_CONDITIONAL([ENABLE_SHELL],
               [test x"$enable_shell" = xyes])
AC_MSG_NOTICE([diagnostics shell: $enable_shell])

# Test module selection

m4_define([DEFINE_TEST_MODULE],
          [AM_CONDITIONAL([$1], [test x"$enable_test_module" = x"$2"])
           AM_COND_IF([$1], [AC_DEFINE_UNQUOTED([X15_RUN_TEST_MODULE], [],
                                                [run test module instead of booting])])])

DEFINE_TEST_MODULE(ENABLE_TEST_LLSYNC_DEFER, llsync_defer)
DEFINE_TEST_MODULE(ENABLE_TEST_MUTEX, mutex)
DEFINE_TEST_MODULE(ENABLE_TEST_MUTEX_PI, mutex_pi)
DEFINE_TEST_MODULE(ENABLE_TEST_PMAP_UPDATE_MP, pmap_update_mp)
DEFINE_TEST_MODULE(ENABLE_TEST_SREF_DIRTY_ZEROES, sref_dirty_zeroes)
DEFINE_TEST_MODULE(ENABLE_TEST_SREF_NOREF, sref_noref)
DEFINE_TEST_MODULE(ENABLE_TEST_SREF_WEAKREF, sref_weakref)
DEFINE_TEST_MODULE(ENABLE_TEST_VM_PAGE_FILL, vm_page_fill)
DEFINE_TEST_MODULE(ENABLE_TEST_XCALL, xcall)

AS_IF([test "$enable_test_module" -a -f test/test_$enable_test_module.c],
      [AC_MSG_NOTICE([test module enabled: $enable_test_module])],
      [test "$enable_test_module"],
      [AC_MSG_ERROR([invalid test module])])

# Thread stack guard selection

AS_IF([test x"$enable_thread_stack_guard" = xyes],
      [AC_DEFINE_UNQUOTED([X15_ENABLE_THREAD_STACK_GUARD], [],
                          [Enable the use of guard pages for thread stacks])])
AC_MSG_NOTICE([thread stack guard pages: $enable_thread_stack_guard])

# Low resolution clock frequency

AC_DEFINE_UNQUOTED([X15_CLOCK_FREQ], [$opt_clock_freq],
                   [low resolution clock frequency])
AC_MSG_NOTICE([low resolution clock frequency: $opt_clock_freq Hz])

# Maximum number of supported processors

AC_DEFINE_UNQUOTED([X15_MAX_CPUS], [$opt_max_cpus],
                   [maximum number of supported processors])
AC_MSG_NOTICE([maximum number of supported processors: $opt_max_cpus])

# Mutex implementation selection

m4_define([SELECT_MUTEX_IMPL],
          [mutex_impl_desc="$2"
           AC_DEFINE_UNQUOTED([$1], [], [$3])])

AS_IF([test x"$opt_mutex_impl" = xadaptive],
      [SELECT_MUTEX_IMPL([X15_USE_MUTEX_ADAPTIVE],
                         [adaptive spinning],
                         [Use adaptive spinning mutex implementation])],
      [test x"$opt_mutex_impl" = xpi],
      [SELECT_MUTEX_IMPL([X15_USE_MUTEX_PI],
                         [priority inheritance],
                         [Use priority inheritance mutex implementation])],
      [test x"$opt_mutex_impl" = xplain],
      [SELECT_MUTEX_IMPL([X15_USE_MUTEX_PLAIN],
                         [plain],
                         [Use plain mutex implementation])],
      [AC_MSG_ERROR([invalid mutex implementation])])
AM_CONDITIONAL([USE_MUTEX_ADAPTIVE],
               [test x"$opt_mutex_impl" = xadaptive])
AM_CONDITIONAL([USE_MUTEX_PI],
               [test x"$opt_mutex_impl" = xpi])
AM_CONDITIONAL([USE_MUTEX_PLAIN],
               [test x"$opt_mutex_impl" = xplain])
AC_MSG_NOTICE([mutex implementation: $mutex_impl_desc])

# Output generation

AS_ECHO

AH_BOTTOM([#include <kern/config.h>])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
