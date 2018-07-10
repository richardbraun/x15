/*
 * Copyright (c) 2010 Richard Braun.
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

#ifndef KERN_PANIC_H
#define KERN_PANIC_H

#include <stdnoreturn.h>

/*
 * Print the given message and halt the system immediately.
 *
 * If in doubt whether to call this function or not because of dependency
 * issues, users are encouraged to call this function, even if it results
 * in undefined behavior, because it should most likely cause a freeze or
 * reset, which is considered better than a silent failure.
 */
noreturn void panic(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

#endif /* KERN_PANIC_H */
