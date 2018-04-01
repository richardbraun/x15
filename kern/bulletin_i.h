/*
 * Copyright (c) 2017-2018 Richard Braun.
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

#ifndef KERN_BULLETIN_I_H
#define KERN_BULLETIN_I_H

#include <kern/list.h>
#include <kern/spinlock.h>

struct bulletin_sub {
    struct list node;
    bulletin_notif_fn_t notif_fn;
    void *arg;
};

struct bulletin {
    struct spinlock lock;
    struct list subs;
};

#endif /* KERN_BULLETIN_I_H */
