/*
 * Copyright (c) 2014-2017 Richard Braun.
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

#include <string.h>

#include <kern/init.h>
#include <kern/list.h>
#include <kern/mutex.h>
#include <kern/printk.h>
#include <kern/spinlock.h>
#include <kern/syscnt.h>

/*
 * Global list of all registered counters.
 */
static struct list syscnt_list;
static struct mutex syscnt_lock;

void __init
syscnt_setup(void)
{
    list_init(&syscnt_list);
    mutex_init(&syscnt_lock);
}

void __init
syscnt_register(struct syscnt *syscnt, const char *name)
{
#ifndef __LP64__
    spinlock_init(&syscnt->lock);
#endif /* __LP64__ */
    syscnt->value = 0;
    strlcpy(syscnt->name, name, sizeof(syscnt->name));

    mutex_lock(&syscnt_lock);
    list_insert_tail(&syscnt_list, &syscnt->node);
    mutex_unlock(&syscnt_lock);
}

void
syscnt_info(const char *prefix)
{
    struct syscnt *syscnt;
    size_t length, prefix_length;
    uint64_t value;

    prefix_length = (prefix == NULL) ? 0 : strlen(prefix);

    printk("syscnt: name                                       count\n");

    mutex_lock(&syscnt_lock);

    list_for_each_entry(&syscnt_list, syscnt, node) {
        if (prefix_length != 0) {
            length = strlen(syscnt->name);

            if ((length < prefix_length)
                || (memcmp(syscnt->name, prefix, prefix_length) != 0)) {
                continue;
            }
        }

        value = syscnt_read(syscnt);

        printk("syscnt: %-30s %17llu\n", syscnt->name,
               (unsigned long long)value);
    }

    mutex_unlock(&syscnt_lock);
}
