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

#include <stdbool.h>
#include <string.h>

#include <kern/console.h>
#include <kern/init.h>
#include <machine/atcons.h>
#include <machine/atkbd.h>
#include <machine/cga.h>

#define ATCONS_ESC_SEQ_MAX_SIZE 8

static struct console atcons_console;

typedef void (*atcons_esc_seq_fn_t)(void);

struct atcons_esc_seq {
    const char *str;
    atcons_esc_seq_fn_t fn;
};

static bool atcons_escape;
static char atcons_esc_seq[ATCONS_ESC_SEQ_MAX_SIZE];
static unsigned int atcons_esc_seq_index;

static void
atcons_process_left(void)
{
    cga_cursor_left();
}

static void
atcons_process_right(void)
{
    cga_cursor_right();
}

static const struct atcons_esc_seq atcons_esc_seqs[] = {
    { "[1D", atcons_process_left },
    { "[1C", atcons_process_right },
};

static void
atcons_reset_esc_seq(void)
{
    atcons_escape = false;
}

static int
atcons_esc_seq_lookup(const struct atcons_esc_seq **seqp)
{
    const struct atcons_esc_seq *seq;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(atcons_esc_seqs); i++) {
        seq = &atcons_esc_seqs[i];

        if (strncmp(seq->str, atcons_esc_seq, atcons_esc_seq_index) == 0) {
            if (strlen(seq->str) == atcons_esc_seq_index) {
                *seqp = seq;
                return 0;
            } else {
                return ERROR_AGAIN;
            }
        }
    }

    return ERROR_SRCH;
}

static void
atcons_process_esc_seq(char c)
{
    const struct atcons_esc_seq *seq;
    int error;

    if (atcons_esc_seq_index >= sizeof(atcons_esc_seq)) {
        atcons_reset_esc_seq();
        return;
    }

    atcons_esc_seq[atcons_esc_seq_index] = c;
    atcons_esc_seq_index++;

    error = atcons_esc_seq_lookup(&seq);

    if (error) {
        if (error != ERROR_AGAIN) {
            atcons_reset_esc_seq();
        }
    } else {
        seq->fn();
        atcons_reset_esc_seq();
    }
}

static void
atcons_putc(struct console *console, char c)
{
    (void)console;

    if (c == '\e') {
        atcons_escape = true;
        atcons_esc_seq_index = 0;
    } else if (atcons_escape) {
        atcons_process_esc_seq(c);
    } else {
        cga_putc(c);
    }
}

static const struct console_ops atcons_ops = {
    .putc = atcons_putc,
};

static int __init
atcons_bootstrap(void)
{
    console_init(&atcons_console, "atcons", &atcons_ops);
    console_register(&atcons_console);
    return 0;
}

INIT_OP_DEFINE(atcons_bootstrap,
               INIT_OP_DEP(cga_setup, true),
               INIT_OP_DEP(console_bootstrap, true));

static int __init
atcons_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(atcons_setup,
               INIT_OP_DEP(atcons_bootstrap, true),
               INIT_OP_DEP(atkbd_setup, true));

void
atcons_intr(const char *s)
{
    console_intr(&atcons_console, s);
}

void
atcons_left(void)
{
    atcons_intr("\e[D");
}

void
atcons_bottom(void)
{
    atcons_intr("\e[B");
}

void
atcons_right(void)
{
    atcons_intr("\e[C");
}

void
atcons_up(void)
{
    atcons_intr("\e[A");
}
