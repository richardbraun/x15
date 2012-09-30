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

#include <kern/panic.h>
#include <kern/printk.h>
#include <machine/cpu.h>

void
panic(const char *format, ...)
{
  va_list list;

  cpu_intr_disable();

  printk("\nkernel panic: ");
  va_start(list, format);
  vprintk(format, list);

  cpu_halt();

  /*
   * Never reached.
   */
}
