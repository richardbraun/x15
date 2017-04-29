/*
 * Copyright (c) 2010 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/limits.h>
#include <kern/types.h>

/*
 * Formatting flags.
 *
 * FORMAT_LOWER must be 0x20 as it is OR'd with digits, eg.
 * '0': 0x30 | 0x20 => 0x30 ('0')
 * 'A': 0x41 | 0x20 => 0x61 ('a')
 */
#define SPRINTF_FORMAT_ALT_FORM     0x01
#define SPRINTF_FORMAT_ZERO_PAD     0x02
#define SPRINTF_FORMAT_LEFT_JUSTIFY 0x04
#define SPRINTF_FORMAT_BLANK        0x08
#define SPRINTF_FORMAT_SIGN         0x10
#define SPRINTF_FORMAT_LOWER        0x20
#define SPRINTF_FORMAT_CONV_SIGNED  0x40

enum {
    SPRINTF_MODIFIER_NONE,
    SPRINTF_MODIFIER_CHAR,
    SPRINTF_MODIFIER_SHORT,
    SPRINTF_MODIFIER_LONG,
    SPRINTF_MODIFIER_LONGLONG,
    SPRINTF_MODIFIER_PTR,       /* Used only for %p */
    SPRINTF_MODIFIER_SIZE,
    SPRINTF_MODIFIER_PTRDIFF
};

enum {
    SPRINTF_SPECIFIER_INVALID,
    SPRINTF_SPECIFIER_INT,
    SPRINTF_SPECIFIER_CHAR,
    SPRINTF_SPECIFIER_STR,
    SPRINTF_SPECIFIER_NRCHARS,
    SPRINTF_SPECIFIER_PERCENT
};

/*
 * Size for the temporary number buffer. The minimum base is 8 so 3 bits
 * are consumed per digit. Add one to round up. The conversion algorithm
 * doesn't use the null byte.
 */
#define SPRINTF_MAX_NUM_SIZE (((sizeof(uint64_t) * CHAR_BIT) / 3) + 1)

/*
 * Special size for vsnprintf(), used by sprintf()/vsprintf() when the
 * buffer size is unknown.
 */
#define SPRINTF_NOLIMIT ((size_t)-1)

static const char sprintf_digits[] = "0123456789ABCDEF";

static inline char *
sprintf_putchar(char *str, char *end, char c)
{
    if (str < end) {
        *str = c;
    }

    str++;

    return str;
}

static inline int
sprintf_isdigit(char c)
{
    return (c >= '0') && (c <= '9');
}

int
sprintf(char *str, const char *format, ...)
{
    va_list ap;
    int length;

    va_start(ap, format);
    length = vsprintf(str, format, ap);
    va_end(ap);

    return length;
}

int
vsprintf(char *str, const char *format, va_list ap)
{
    return vsnprintf(str, SPRINTF_NOLIMIT, format, ap);
}

int
snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int length;

    va_start(ap, format);
    length = vsnprintf(str, size, format, ap);
    va_end(ap);

    return length;
}

int
vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    unsigned long long n;
    int i, len, found, flags, width, precision, modifier, specifier, shift;
    unsigned char r, base, mask;
    char c, *s, *start, *end, sign, tmp[SPRINTF_MAX_NUM_SIZE];

    start = str;

    if (size == 0) {
        end = NULL;
    } else if (size == SPRINTF_NOLIMIT) {
        end = (char *)-1;
    } else {
        end = start + size - 1;
    }

    while ((c = *format) != '\0') {
        if (c != '%') {
            str = sprintf_putchar(str, end, c);
            format++;
            continue;
        }

        /* Flags */

        found = 1;
        flags = 0;

        do {
            format++;
            c = *format;

            switch (c) {
            case '#':
                flags |= SPRINTF_FORMAT_ALT_FORM;
                break;
            case '0':
                flags |= SPRINTF_FORMAT_ZERO_PAD;
                break;
            case '-':
                flags |= SPRINTF_FORMAT_LEFT_JUSTIFY;
                break;
            case ' ':
                flags |= SPRINTF_FORMAT_BLANK;
                break;
            case '+':
                flags |= SPRINTF_FORMAT_SIGN;
                break;
            default:
                found = 0;
                break;
            }
        } while (found);

        /* Width */

        if (sprintf_isdigit(c)) {
            width = 0;

            while (sprintf_isdigit(c)) {
                width = width * 10 + (c - '0');
                format++;
                c = *format;
            }
        } else if (c == '*') {
            width = va_arg(ap, int);

            if (width < 0) {
                flags |= SPRINTF_FORMAT_LEFT_JUSTIFY;
                width = -width;
            }

            format++;
            c = *format;
        } else {
            width = 0;
        }

        /* Precision */

        if (c == '.') {
            format++;
            c = *format;

            if (sprintf_isdigit(c)) {
                precision = 0;

                while (sprintf_isdigit(c)) {
                    precision = precision * 10 + (c - '0');
                    format++;
                    c = *format;
                }
            } else if (c == '*') {
                precision = va_arg(ap, int);

                if (precision < 0) {
                    precision = 0;
                }

                format++;
                c = *format;
            } else {
                precision = 0;
            }
        } else {
            /* precision is >= 0 only if explicit */
            precision = -1;
        }

        /* Length modifier */

        switch (c) {
        case 'h':
        case 'l':
            format++;

            if (c == *format) {
                modifier = (c == 'h')
                           ? SPRINTF_MODIFIER_CHAR
                           : SPRINTF_MODIFIER_LONGLONG;
                goto skip_modifier;
            } else {
                modifier = (c == 'h')
                           ? SPRINTF_MODIFIER_SHORT
                           : SPRINTF_MODIFIER_LONG;
                c = *format;
            }

            break;
        case 'z':
            modifier = SPRINTF_MODIFIER_SIZE;
            goto skip_modifier;
        case 't':
            modifier = SPRINTF_MODIFIER_PTRDIFF;
skip_modifier:
            format++;
            c = *format;
            break;
        default:
            modifier = SPRINTF_MODIFIER_NONE;
            break;
        }

        /* Specifier */

        switch (c) {
        case 'd':
        case 'i':
            flags |= SPRINTF_FORMAT_CONV_SIGNED;
        case 'u':
            base = 10;
            goto integer;
        case 'o':
            base = 8;
            goto integer;
        case 'p':
            flags |= SPRINTF_FORMAT_ALT_FORM;
            modifier = SPRINTF_MODIFIER_PTR;
        case 'x':
            flags |= SPRINTF_FORMAT_LOWER;
        case 'X':
            base = 16;
integer:
            specifier = SPRINTF_SPECIFIER_INT;
            break;
        case 'c':
            specifier = SPRINTF_SPECIFIER_CHAR;
            break;
        case 's':
            specifier = SPRINTF_SPECIFIER_STR;
            break;
        case 'n':
            specifier = SPRINTF_SPECIFIER_NRCHARS;
            break;
        case '%':
            specifier = SPRINTF_SPECIFIER_PERCENT;
            break;
        default:
            specifier = SPRINTF_SPECIFIER_INVALID;
            break;
        }

        /* Output */

        switch (specifier) {
        case SPRINTF_SPECIFIER_INT:
            switch (modifier) {
            case SPRINTF_MODIFIER_CHAR:
                if (flags & SPRINTF_FORMAT_CONV_SIGNED) {
                    n = (signed char)va_arg(ap, int);
                } else {
                    n = (unsigned char)va_arg(ap, int);
                }
                break;
            case SPRINTF_MODIFIER_SHORT:
                if (flags & SPRINTF_FORMAT_CONV_SIGNED) {
                    n = (short)va_arg(ap, int);
                } else {
                    n = (unsigned short)va_arg(ap, int);
                }
                break;
            case SPRINTF_MODIFIER_LONG:
                if (flags & SPRINTF_FORMAT_CONV_SIGNED) {
                    n = va_arg(ap, long);
                } else {
                    n = va_arg(ap, unsigned long);
                }
                break;
            case SPRINTF_MODIFIER_LONGLONG:
                if (flags & SPRINTF_FORMAT_CONV_SIGNED) {
                    n = va_arg(ap, long long);
                } else {
                    n = va_arg(ap, unsigned long long);
                }
                break;
            case SPRINTF_MODIFIER_PTR:
                n = (uintptr_t)va_arg(ap, void *);
                break;
            case SPRINTF_MODIFIER_SIZE:
                if (flags & SPRINTF_FORMAT_CONV_SIGNED) {
                    n = va_arg(ap, ssize_t);
                } else {
                    n = va_arg(ap, size_t);
                }
                break;
            case SPRINTF_MODIFIER_PTRDIFF:
                n = va_arg(ap, ptrdiff_t);
                break;
            default:
                if (flags & SPRINTF_FORMAT_CONV_SIGNED) {
                    n = va_arg(ap, int);
                } else {
                    n = va_arg(ap, unsigned int);
                }
                break;
            }

            if ((flags & SPRINTF_FORMAT_LEFT_JUSTIFY) || (precision >= 0)) {
                flags &= ~SPRINTF_FORMAT_ZERO_PAD;
            }

            sign = 0;

            if (flags & SPRINTF_FORMAT_ALT_FORM) {
                /* '0' for octal */
                width--;

                /* '0x' or '0X' for hexadecimal */
                if (base == 16) {
                    width--;
                }
            } else if (flags & SPRINTF_FORMAT_CONV_SIGNED) {
                if ((long long)n < 0) {
                    sign = '-';
                    width--;
                    n = -(long long)n;
                } else if (flags & SPRINTF_FORMAT_SIGN) {
                    /* SPRINTF_FORMAT_SIGN must precede SPRINTF_FORMAT_BLANK. */
                    sign = '+';
                    width--;
                } else if (flags & SPRINTF_FORMAT_BLANK) {
                    sign = ' ';
                    width--;
                }
            }

            /* Conversion, in reverse order */

            i = 0;

            if (n == 0) {
                if (precision != 0) {
                    tmp[i++] = '0';
                }
            } else if (base == 10) {
                /*
                 * Try to avoid 64 bits operations if the processor doesn't
                 * support them. Note that even when using modulus and
                 * division operators close to each other, the compiler will
                 * forge two calls to __udivdi3() and __umoddi3() instead of
                 * one to __udivmoddi3(), whereas processor instructions are
                 * generally correctly used once, giving both the remainder
                 * and the quotient, through plain or reciprocal division.
                 */
#ifndef __LP64__
                if (modifier == SPRINTF_MODIFIER_LONGLONG) {
#endif /* __LP64__ */
                    do {
                        r = n % 10;
                        n /= 10;
                        tmp[i++] = sprintf_digits[r];
                    } while (n != 0);
#ifndef __LP64__
                } else {
                    unsigned long m;

                    m = (unsigned long)n;

                    do {
                        r = m % 10;
                        m /= 10;
                        tmp[i++] = sprintf_digits[r];
                    } while (m != 0);
                }
#endif /* __LP64__ */
            } else {
                mask = base - 1;
                shift = (base == 8) ? 3 : 4;

                do {
                    r = (unsigned char)n & mask;
                    n >>= shift;
                    tmp[i++] = sprintf_digits[r]
                               | (flags & SPRINTF_FORMAT_LOWER);
                } while (n != 0);
            }

            if (i > precision) {
                precision = i;
            }

            width -= precision;

            if (!(flags & (SPRINTF_FORMAT_LEFT_JUSTIFY
                           | SPRINTF_FORMAT_ZERO_PAD)))
                while (width-- > 0) {
                    str = sprintf_putchar(str, end, ' ');
                }

            if (flags & SPRINTF_FORMAT_ALT_FORM) {
                str = sprintf_putchar(str, end, '0');

                if (base == 16)
                    str = sprintf_putchar(str, end,
                                          'X' | (flags & SPRINTF_FORMAT_LOWER));
            } else if (sign) {
                str = sprintf_putchar(str, end, sign);
            }

            if (!(flags & SPRINTF_FORMAT_LEFT_JUSTIFY)) {
                c = (flags & SPRINTF_FORMAT_ZERO_PAD) ? '0' : ' ';

                while (width-- > 0) {
                    str = sprintf_putchar(str, end, c);
                }
            }

            while (i < precision--) {
                str = sprintf_putchar(str, end, '0');
            }

            while (i-- > 0) {
                str = sprintf_putchar(str, end, tmp[i]);
            }

            while (width-- > 0) {
                str = sprintf_putchar(str, end, ' ');
            }

            break;
        case SPRINTF_SPECIFIER_CHAR:
            c = (unsigned char)va_arg(ap, int);

            if (!(flags & SPRINTF_FORMAT_LEFT_JUSTIFY))
                while (--width > 0) {
                    str = sprintf_putchar(str, end, ' ');
                }

            str = sprintf_putchar(str, end, c);

            while (--width > 0) {
                str = sprintf_putchar(str, end, ' ');
            }

            break;
        case SPRINTF_SPECIFIER_STR:
            s = va_arg(ap, char *);

            if (s == NULL) {
                s = "(null)";
            }

            len = 0;

            for (len = 0; s[len] != '\0'; len++)
                if (len == precision) {
                    break;
                }

            if (!(flags & SPRINTF_FORMAT_LEFT_JUSTIFY))
                while (len < width--) {
                    str = sprintf_putchar(str, end, ' ');
                }

            for (i = 0; i < len; i++) {
                str = sprintf_putchar(str, end, *s);
                s++;
            }

            while (len < width--) {
                str = sprintf_putchar(str, end, ' ');
            }

            break;
        case SPRINTF_SPECIFIER_NRCHARS:
            if (modifier == SPRINTF_MODIFIER_CHAR) {
                signed char *ptr = va_arg(ap, signed char *);
                *ptr = str - start;
            } else if (modifier == SPRINTF_MODIFIER_SHORT) {
                short *ptr = va_arg(ap, short *);
                *ptr = str - start;
            } else if (modifier == SPRINTF_MODIFIER_LONG) {
                long *ptr = va_arg(ap, long *);
                *ptr = str - start;
            } else if (modifier == SPRINTF_MODIFIER_LONGLONG) {
                long long *ptr = va_arg(ap, long long *);
                *ptr = str - start;
            } else if (modifier == SPRINTF_MODIFIER_SIZE) {
                ssize_t *ptr = va_arg(ap, ssize_t *);
                *ptr = str - start;
            } else if (modifier == SPRINTF_MODIFIER_PTRDIFF) {
                ptrdiff_t *ptr = va_arg(ap, ptrdiff_t *);
                *ptr = str - start;
            } else {
                int *ptr = va_arg(ap, int *);
                *ptr = str - start;
            }

            break;
        case SPRINTF_SPECIFIER_PERCENT:
        case SPRINTF_SPECIFIER_INVALID:
            str = sprintf_putchar(str, end, '%');
            break;
        default:
            break;
        }

        if (specifier != SPRINTF_SPECIFIER_INVALID) {
            format++;
        }
    }

    if (str < end) {
        *str = '\0';
    } else if (end != NULL) {
        *end = '\0';
    }

    return str - start;
}
