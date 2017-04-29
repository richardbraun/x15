AC_DEFUN([AX_PROG_HIGHLIGHT],
         [AC_ARG_VAR([HIGHLIGHT], [path to highlight command])
          AC_CHECK_PROG([HIGHLIGHT], [highlight], [highlight])
          AS_IF([test x"$HIGHLIGHT" = x], [$1])
          AM_CONDITIONAL([HAVE_HIGHLIGHT], [test x"$HIGHLIGHT" != x])])
