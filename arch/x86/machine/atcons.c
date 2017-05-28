/*
 * Copyright (c) 2017 Richard Braun.
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

#include <kern/console.h>
#include <kern/init.h>
#include <machine/atcons.h>
#include <machine/atkbd.h>
#include <machine/cga.h>

static struct console atcons_console;

static void
atcons_putc(struct console *console, char c)
{
    (void)console;
    cga_putc(c);
}

static const struct console_ops atcons_ops = {
    .putc = atcons_putc,
};

void __init
atcons_bootstrap(void)
{
    cga_setup();

    console_init(&atcons_console, "atcons", &atcons_ops);
    console_register(&atcons_console);
}

void __init
atcons_setup(void)
{
    atkbd_setup();
}

void
atcons_intr(char c)
{
    console_intr(&atcons_console, c);
}
