AC_DEFUN([AX_PROG_A2X],
         [AC_ARG_VAR([A2X], [path to a2x command])
          AC_CHECK_PROG([A2X], [a2x], [a2x])
          AS_IF([test x"$A2X" = x], [$1])
          AM_CONDITIONAL([HAVE_A2X], [test x"$A2X" != x])])
