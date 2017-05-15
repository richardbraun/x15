/*
 * Copyright (c) 2011 Richard Braun.
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

#ifndef _X86_PIT_H
#define _X86_PIT_H

/*
 * Initialize the PIT as a free running counter.
 *
 * This is used during early initialization to measure the frequency of
 * other clocks. The PIT is used despite its lack of precision because
 * it's the only architectural timer with a known frequency.
 */
void pit_setup_free_running(void);

/*
 * Initialize the pit module.
 */
void pit_setup(void);

/*
 * Wait (without sleeping) until the specified amount of time has elapsed.
 */
void pit_delay(unsigned long usecs);

#endif /* _X86_PIT_H */
