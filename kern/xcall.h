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
 *
 *
 * Cross-processor function calls.
 *
 * This module provides the ability to run functions, called cross-calls,
 * on specific processors.
 */

#ifndef _KERN_XCALL_H
#define _KERN_XCALL_H

/*
 * Type for cross-call functions.
 */
typedef void (*xcall_fn_t)(void *arg);

/*
 * Run the given cross-call function on a specific processor.
 *
 * The operation is completely synchronous, returning only when the function
 * has finished running on the target processor, with the side effects of
 * the function visible.
 *
 * The function is run in interrupt context. Interrupts must be enabled
 * when calling this function.
 */
void xcall_call(xcall_fn_t fn, void *arg, unsigned int cpu);

/*
 * Report a cross-call interrupt from a remote processor.
 *
 * Called from interrupt context.
 */
void xcall_intr(void);

#endif /* _KERN_XCALL_H */
