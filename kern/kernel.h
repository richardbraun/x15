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

#ifndef _KERN_KERNEL_H
#define _KERN_KERNEL_H

#include <kern/printk.h>

/*
 * Kernel properties.
 */
#define KERNEL_NAME     PACKAGE_NAME
#define KERNEL_VERSION  PACKAGE_VERSION

static inline void
kernel_show_banner(void)
{
    printk(KERNEL_NAME " " KERNEL_VERSION "\n");
}

void kernel_main(void);

#endif /* _KERN_KERNEL_H */
