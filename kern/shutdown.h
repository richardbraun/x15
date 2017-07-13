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

#ifndef _KERN_SHUTDOWN_H
#define _KERN_SHUTDOWN_H

#include <stdnoreturn.h>

#include <kern/init.h>
#include <kern/plist.h>

struct shutdown_ops {
    struct plist_node node;
    void (*reset)(void);
};

void shutdown_register(struct shutdown_ops *ops, unsigned int priority);

noreturn void shutdown_halt(void);
noreturn void shutdown_reboot(void);

/*
 * This init operation provides :
 *  - registration of shutdown operations
 */
INIT_OP_DECLARE(shutdown_bootstrap);

/*
 * This init operation provides :
 *  - all shutdown operations have been registered
 *  - module fully initialized
 */
INIT_OP_DECLARE(shutdown_setup);

#endif /* _KERN_SHUTDOWN_H */
