/*
 * Copyright (c) 2010-2017 Richard Braun.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Formatted string functions.
 *
 * The functions provided by this module implement a subset of the standard
 * sprintf- and sscanf-like functions.
 *
 * sprintf:
 *  - flags: # 0 - ' ' (space) +
 *  - field width is supported
 *  - precision is supported
 *
 * sscanf:
 *  - flags: *
 *  - field width is supported
 *
 * common:
 *  - modifiers: hh h l ll z t
 *  - specifiers: d i o u x X c s p n %
 *
 *
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 */

#ifndef _FMT_H
#define _FMT_H

#include <stdarg.h>
#include <stddef.h>

int fmt_sprintf(char *str, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

int fmt_vsprintf(char *str, const char *format, va_list ap)
    __attribute__((format(printf, 2, 0)));

int fmt_snprintf(char *str, size_t size, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

int fmt_vsnprintf(char *str, size_t size, const char *format, va_list ap)
    __attribute__((format(printf, 3, 0)));

int fmt_sscanf(const char *str, const char *format, ...)
    __attribute__((format(scanf, 2, 3)));

int fmt_vsscanf(const char *str, const char *format, va_list ap)
    __attribute__((format(scanf, 2, 0)));

#endif /* _FMT_H */
