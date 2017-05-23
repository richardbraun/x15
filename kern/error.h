/*
 * Copyright (c) 2012-2017 Richard Braun.
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

#ifndef _KERN_ERROR_H
#define _KERN_ERROR_H

#define ERROR_NOMEM 1
#define ERROR_AGAIN 2
#define ERROR_INVAL 3
#define ERROR_BUSY  4
#define ERROR_FAULT 5
#define ERROR_NODEV 6

/*
 * Return a string describing the given error.
 */
const char * error_str(int error);

/*
 * If error denotes an actual error (i.e. is not 0), panic, using the given
 * string as a prefix for the error message. A NULL prefix is allowed.
 */
void error_check(int error, const char *prefix);

#endif /* _KERN_ERROR_H */
