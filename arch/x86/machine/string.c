/*
 * Copyright (c) 2014 Richard Braun.
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
 * Despite comparison and scan instructions not having side-effects, the
 * memory clobber is used because the compiler cannot infer dependencies
 * on the memory referenced by the pointers.
 */

#include <stddef.h>
#include <string.h>

#include <kern/macros.h>
#include <machine/string.h>

#ifdef STRING_ARCH_MEMCPY
void *
memcpy(void *dest, const void *src, size_t n)
{
    void *orig_dest;

    orig_dest = dest;
    asm volatile("rep movsb"
                 : "+D" (dest), "+S" (src), "+c" (n)
                 : : "memory");
    return orig_dest;
}
#endif /* STRING_ARCH_MEMCPY */

#ifdef STRING_ARCH_MEMMOVE
void *
memmove(void *dest, const void *src, size_t n)
{
    void *orig_dest;

    orig_dest = dest;

    if (dest <= src) {
        asm volatile("rep movsb"
                     : "+D" (dest), "+S" (src), "+c" (n)
                     : : "memory");
    } else {
        dest += n - 1;
        src += n - 1;
        asm volatile("std; rep movsb; cld"
                     : "+D" (dest), "+S" (src), "+c" (n)
                     : : "memory");
    }

    return orig_dest;
}
#endif /* STRING_ARCH_MEMMOVE */

#ifdef STRING_ARCH_MEMSET
void *
memset(void *s, int c, size_t n)
{
    void *orig_s;

    orig_s = s;
    asm volatile("rep stosb"
                 : "+D" (s), "+c" (n)
                 : "a" (c)
                 : "memory");
    return orig_s;
}
#endif /* STRING_ARCH_MEMSET */

#ifdef STRING_ARCH_MEMCMP
int
memcmp(const void *s1, const void *s2, size_t n)
{
    unsigned char c1, c2;

    if (n == 0) {
        return 0;
    }

    asm volatile("repe cmpsb"
                 : "+D" (s1), "+S" (s2), "+c" (n)
                 : : "memory");
    c1 = *(((const unsigned char *)s1) - 1);
    c2 = *(((const unsigned char *)s2) - 1);
    return (int)c1 - (int)c2;
}
#endif /* STRING_ARCH_MEMCMP */

#ifdef STRING_ARCH_STRLEN
size_t
strlen(const char *s)
{
    size_t n;

    n = (size_t)-1;
    asm volatile("repne scasb"
                 : "+D" (s), "+c" (n)
                 : "a" (0)
                 : "memory");
    return (size_t)-2 - n;
}
#endif /* STRING_ARCH_STRLEN */

#ifdef STRING_ARCH_STRCPY
char *
strcpy(char *dest, const char *src)
{
    char *orig_dest;

    orig_dest = dest;
    asm volatile("1:\n"
                 "lodsb\n"
                 "stosb\n"
                 "testb %%al, %%al\n"
                 "jnz 1b\n"
                 : "+D" (dest), "+S" (src)
                 : : "al", "memory");
    return orig_dest;
}
#endif /* STRING_ARCH_STRCPY */

#ifdef STRING_ARCH_STRCMP
int
strcmp(const char *s1, const char *s2)
{
    unsigned char c1, c2;

    asm volatile("1:\n"
                 "lodsb\n"
                 "scasb\n"
                 "jne 1f\n"
                 "testb %%al, %%al\n"
                 "jnz 1b\n"
                 "1:\n"
                 : "+D" (s1), "+S" (s2)
                 : : "al", "memory");
    c1 = *(((const unsigned char *)s1) - 1);
    c2 = *(((const unsigned char *)s2) - 1);
    return (int)c1 - (int)c2;
}
#endif /* STRING_ARCH_STRCMP */

#ifdef STRING_ARCH_STRNCMP
int
strncmp(const char *s1, const char *s2, size_t n)
{
    unsigned char c1, c2;

    if (unlikely(n == 0)) {
        return 0;
    }

    asm volatile("1:\n"
                 "lodsb\n"
                 "scasb\n"
                 "jne 1f\n"
                 "testb %%al, %%al\n"
                 "jz 1f\n"
                 "dec %2\n"
                 "jnz 1b\n"
                 "1:\n"
                 : "+D" (s1), "+S" (s2), "+c" (n)
                 : : "al", "memory");
    c1 = *(((const unsigned char *)s1) - 1);
    c2 = *(((const unsigned char *)s2) - 1);
    return (int)c1 - (int)c2;
}
#endif /* STRING_ARCH_STRNCMP */

#ifdef STRING_ARCH_STRCHR
char *
strchr(const char *s, int c)
{
    asm volatile("1:\n"
                 "lodsb\n"
                 "cmpb %%al, %1\n"
                 "je 1f\n"
                 "testb %%al, %%al\n"
                 "jnz 1b\n"
                 "mov $1, %0\n"
                 "1:\n"
                 "dec %0\n"
                 : "+S" (s)
                 : "c" ((char)c)
                 : "al", "memory");
    return (char *)s;
}
#endif /* STRING_ARCH_STRCHR */
