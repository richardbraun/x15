/*
 * Copyright (c) 2012-2017 Richard Braun.
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
 *
 *
 * Trivial, portable implementations.
 */

#include <stddef.h>
#include <string.h>

#include <kern/param.h>

#ifndef ARCH_STRING_MEMCPY
void *
memcpy(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;
    size_t i;

    dest_ptr = dest;
    src_ptr = src;

    for (i = 0; i < n; i++) {
        *dest_ptr++ = *src_ptr++;
    }

    return dest;
}
#endif /* ARCH_STRING_MEMCPY */

#ifndef ARCH_STRING_MEMMOVE
void *
memmove(void *dest, const void *src, size_t n)
{
    const char *src_ptr;
    char *dest_ptr;
    size_t i;

    if (dest <= src) {
        dest_ptr = dest;
        src_ptr = src;

        for (i = 0; i < n; i++) {
            *dest_ptr++ = *src_ptr++;
        }
    } else {
        dest_ptr = dest + n - 1;
        src_ptr = src + n - 1;

        for (i = 0; i < n; i++) {
            *dest_ptr-- = *src_ptr--;
        }
    }

    return dest;
}
#endif /* ARCH_STRING_MEMMOVE */

#ifndef ARCH_STRING_MEMSET
void *
memset(void *s, int c, size_t n)
{
    char *buffer;
    size_t i;

    buffer = s;

    for (i = 0; i < n; i++) {
        buffer[i] = c;
    }

    return s;
}
#endif /* ARCH_STRING_MEMSET */

#ifndef ARCH_STRING_MEMCMP
int
memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *a1, *a2;
    size_t i;

    a1 = s1;
    a2 = s2;

    for (i = 0; i < n; i++)
        if (a1[i] != a2[i]) {
            return (int)a1[i] - (int)a2[i];
        }

    return 0;
}
#endif /* ARCH_STRING_MEMCMP */

#ifndef ARCH_STRING_STRLEN
size_t
strlen(const char *s)
{
    size_t i;

    i = 0;

    while (*s++ != '\0') {
        i++;
    }

    return i;
}
#endif /* ARCH_STRING_STRLEN */

#ifndef ARCH_STRING_STRCPY
char *
strcpy(char *dest, const char *src)
{
    char *tmp;

    tmp = dest;

    while ((*dest = *src) != '\0') {
        dest++;
        src++;
    }

    return tmp;
}
#endif /* ARCH_STRING_STRCPY */

size_t
strlcpy(char *dest, const char *src, size_t n)
{
    size_t len;

    len = strlen(src);

    if (n == 0) {
        goto out;
    }

    n = (len < n) ? len : n - 1;
    memcpy(dest, src, n);
    dest[n] = '\0';

out:
    return len;
}

#ifndef ARCH_STRING_STRCMP
int
strcmp(const char *s1, const char *s2)
{
    char c1, c2;

    while ((c1 = *s1) == (c2 = *s2)) {
        if (c1 == '\0') {
            return 0;
        }

        s1++;
        s2++;
    }

    return (int)c1 - (int)c2;
}
#endif /* ARCH_STRING_STRCMP */

#ifndef ARCH_STRING_STRNCMP
int
strncmp(const char *s1, const char *s2, size_t n)
{
    char c1, c2;

    c1 = '\0';
    c2 = '\0';

    while ((n != 0) && (c1 = *s1) == (c2 = *s2)) {
        if (c1 == '\0') {
            return 0;
        }

        n--;
        s1++;
        s2++;
    }

    return (int)c1 - (int)c2;
}
#endif /* ARCH_STRING_STRNCMP */

#ifndef ARCH_STRING_STRCHR
char *
strchr(const char *s, int c)
{
    for (;;) {
        if (*s == c) {
            return (char *)s;
        } else if (*s == '\0') {
            return NULL;
        }

        s++;
    }
}
#endif /* ARCH_STRING_STRCHR */
