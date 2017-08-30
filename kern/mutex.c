/*
 * Copyright (c) 2013-2017 Richard Braun.
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

#include <kern/init.h>
#include <kern/mutex.h>
#include <kern/thread.h>

static int __init
mutex_setup(void)
{
    return 0;
}

INIT_OP_DEFINE(mutex_setup,
               INIT_OP_DEP(mutex_impl_setup, true),
               INIT_OP_DEP(thread_setup_booter, true));
