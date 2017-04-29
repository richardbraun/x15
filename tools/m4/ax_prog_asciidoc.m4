AC_DEFUN([AX_PROG_ASCIIDOC],
         [AC_ARG_VAR([ASCIIDOC], [path to asciidoc command])
          AC_CHECK_PROG([ASCIIDOC], [asciidoc], [asciidoc])
          AS_IF([test x"$ASCIIDOC" = x], [$1])
          AM_CONDITIONAL([HAVE_ASCIIDOC], [test x"$ASCIIDOC" != x])])
