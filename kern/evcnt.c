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
 */

#include <kern/evcnt.h>
#include <kern/init.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/printk.h>
#include <kern/string.h>

/*
 * Global list of all registered counters.
 */
static struct list evcnt_list;
static struct mutex evcnt_mutex;

void __init
evcnt_setup(void)
{
    list_init(&evcnt_list);
    mutex_init(&evcnt_mutex);
}

void
evcnt_register(struct evcnt *evcnt, const char *name)
{
    evcnt->count = 0;
    strlcpy(evcnt->name, name, sizeof(evcnt->name));

    mutex_lock(&evcnt_mutex);
    list_insert_tail(&evcnt_list, &evcnt->node);
    mutex_unlock(&evcnt_mutex);
}

void
evcnt_info(void)
{
    struct evcnt *evcnt;

    printk("evcnt: name                               count\n");

    mutex_lock(&evcnt_mutex);

    list_for_each_entry(&evcnt_list, evcnt, node)
        printk("evcnt: %-24s %15llu\n", evcnt->name, evcnt->count);

    mutex_unlock(&evcnt_mutex);
}
