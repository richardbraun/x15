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
 * Tiny 8250 UART driver.
 */

#ifndef _X86_UART_H
#define _X86_UART_H

/*
 * Early initialization of the uart module.
 *
 * Devices may only be used to report diagnostics until initialization
 * is completed.
 */
void uart_bootstrap(void);

/*
 * Initialize the uart module.
 *
 * On return, devices may be used for both input and output, using interrupts.
 */
void uart_setup(void);

/*
 * Display device information.
 */
void uart_info(void);

#endif /* _X86_UART_H */
