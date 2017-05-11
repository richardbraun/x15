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
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/assert.h>
#include <kern/init.h>
#include <kern/macros.h>
#include <kern/panic.h>

/*
 * Internally, all space characters are turned into null bytes so that
 * values returned to callers directly point in the command line string,
 * with no need for dynamic allocation.
 */
static char arg_cmdline[ARG_CMDLINE_MAX_SIZE] __initdata;
static const char *arg_cmdline_end __initdata;

void __init
arg_setup(const char *cmdline)
{
    size_t i, length;

    if (cmdline == NULL) {
        arg_cmdline[0] = '\0';
        return;
    }

    length = strlen(cmdline);

    if ((length + 1) > ARRAY_SIZE(arg_cmdline)) {
        panic("arg: command line too long");
    }

    memcpy(arg_cmdline, cmdline, length + 1);

    for (i = 0; i < length; i++) {
        if (arg_cmdline[i] == ' ') {
            arg_cmdline[i] = '\0';
        }
    }

    arg_cmdline_end = arg_cmdline + length;
}

void __init
arg_info(void)
{
    printf("arg: %s\n", arg_cmdline);
}

static const char * __init
arg_walk(const char *s)
{
    if (s == NULL) {
        s = arg_cmdline;
    } else {
        for (;;) {
            if (s >= arg_cmdline_end) {
                return NULL;
            }

            if (*s == '\0') {
                break;
            }

            s++;
        }
    }

    for (;;) {
        if (s >= arg_cmdline_end) {
            return NULL;
        }

        if (*s != '\0') {
            return s;
        }

        s++;
    }
}

static const char * __init
arg_find_name_end(const char *arg)
{
    const char *end;

    end = strchr(arg, '=');

    if (end == NULL) {
        end = arg + strlen(arg);
    }

    return end;
}

static const char * __init
arg_find(const char *name)
{
    const char *arg, *arg_name_end;
    size_t arg_name_length, name_length;

    name_length = strlen(name);
    assert(name_length != 0);

    for (arg = arg_walk(NULL); arg != NULL; arg = arg_walk(arg)) {
        arg_name_end = arg_find_name_end(arg);
        arg_name_length = arg_name_end - arg;

        if ((arg_name_length == name_length)
            && (memcmp(arg, name, name_length) == 0)) {
            return arg;
        }
    }

    return NULL;
}

bool __init
arg_present(const char *name)
{
    return (arg_find(name) != NULL);
}

const char * __init
arg_value(const char *name)
{
    const char *arg, *value;

    arg = arg_find(name);

    if (arg == NULL) {
        return NULL;
    }

    value = strchr(arg, '=');

    if (value == NULL) {
        return "";
    }

    return value + 1;
}
