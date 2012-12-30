/*
 * Copyright (c) 2012 Richard Braun.
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

#include <kern/printk.h>
#include <kern/stddef.h>
#include <kern/types.h>
#include <machine/pmap.h>
#include <machine/strace.h>

#ifdef __LP64__
#define STRACE_ADDR_FORMAT "%#018lx"
#else /* __LP64__ */
#define STRACE_ADDR_FORMAT "%#010lx"
#endif /* __LP64__ */

static void
strace_show_one(unsigned int index, unsigned long ip)
{
    printk("strace: #%u [" STRACE_ADDR_FORMAT "]\n", index, ip);
}

void
strace_show(unsigned long ip, unsigned long bp)
{
    phys_addr_t pa;
    void **frame;
    unsigned int i;

    printk("strace: stack trace:\n");
    strace_show_one(0, ip);

    i = 1;
    frame = (void **)bp;

    for (;;) {
        if (frame == NULL)
            break;

        pa = pmap_kextract((unsigned long)&frame[1]);

        if (pa == 0) {
            printk("strace: unmapped return address at %p\n", &frame[1]);
            break;
        }

        strace_show_one(i, (unsigned long)frame[1]);
        pa = pmap_kextract((unsigned long)frame);

        if (pa == 0) {
            printk("strace: unmapped frame address at %p\n", frame);
            break;
        }

        i++;
        frame = frame[0];
    }

    printk("strace: end of trace\n");
}
