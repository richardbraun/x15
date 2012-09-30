AC_INIT([X15], [0.1], [rbraun@sceen.net], [x15])

AC_CONFIG_SRCDIR([kern/printk.c])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([gnu check-news subdir-objects 1.10])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])],
                            [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])

AC_PREFIX_DEFAULT([])


#
# Deduce the output variable `systype' from the configuration parameters.
#
AC_CANONICAL_HOST

AS_CASE(["$host_cpu"],
        [i?86|x86_64], [m4_include([arch/i386/configfrag.ac])],
        [AC_MSG_ERROR([unsuported CPU type])])

AC_SUBST([systype])


#
# Arguments to configure
#
AC_ARG_ENABLE([debug],
              [AS_HELP_STRING([--disable-debug],
                              [disable the debugging facilities])])

AC_ARG_WITH([max-cpus],
            [AS_HELP_STRING([--with-max-cpus=MAX_CPUS],
                            [set the maximum number of supported processors])],
            [opt_max_cpus=$withval],
            [opt_max_cpus=32])


#
# Options
#
AS_IF([test x"$enable_debug" = xno],
  [AC_DEFINE([NDEBUG], [1], [general debugging])])

AC_DEFINE([__KERNEL__], [1], [kernel code])

AC_DEFINE_UNQUOTED([ARCH], [$systype], [arch])
AM_CONDITIONAL([I386], [test "$systype" = i386])

AC_DEFINE_UNQUOTED([MAX_CPUS], [$opt_max_cpus], [maximum number of supported processors])


#
# Programs.
#
AM_PROG_AS
AC_PROG_CC([gcc])
AC_PROG_CPP
AC_PROG_RANLIB

AM_PROG_CC_C_O

#
# Output
#
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
