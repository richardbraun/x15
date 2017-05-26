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
 *
 *
 * Machine-independent interrupt management.
 */

#ifndef _KERN_INTR_H
#define _KERN_INTR_H

/*
 * Type for interrupt handler functions.
 *
 * Return codes :
 *  - 0             Interrupt successfully handled
 *  - ERROR_AGAIN   Spurious interrupt
 */
typedef int (*intr_handler_fn_t)(void *arg);

/*
 * Operations of an interrupt controller.
 *
 * Operations for interrupts targeting the same processor are serialized.
 */
struct intr_ops {
    void (*enable)(void *priv, unsigned int intr, unsigned int cpu);
    void (*disable)(void *priv, unsigned int intr);
    void (*eoi)(void *priv, unsigned int intr);
};

/*
 * Initialize the intr module.
 */
void intr_setup(void);

/*
 * Register an interrupt controller.
 *
 * This function isn't thread-safe and can only be called during system
 * initialization.
 */
void intr_register_ctl(const struct intr_ops *ops, void *priv,
                       unsigned int first_intr, unsigned int last_intr);

/*
 * Register/unregister an interrupt handler.
 */
int intr_register(unsigned int intr, intr_handler_fn_t fn, void *arg);
void intr_unregister(unsigned int intr, intr_handler_fn_t fn);

/*
 * Handle an interrupt.
 */
void intr_handle(unsigned int intr);

#endif /* _KERN_INTR_H */
