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
 */

#include <kern/error.h>
#include <kern/panic.h>

void
error_check(int error, const char *prefix)
{
    const char *msg;

    switch (error) {
    case 0:
        return;
    case ERROR_NOMEM:
        msg = "out of memory";
        break;
    case ERROR_AGAIN:
        msg = "resource temporarily unavailable";
        break;
    case ERROR_INVAL:
        msg = "invalid argument";
        break;
    case ERROR_BUSY:
        msg = "device or resource busy";
        break;
    default:
        msg = "unknown error";
    }

    panic("%s%s%s",
          (prefix == NULL) ? "" : prefix,
          (prefix == NULL) ? "" : ": ",
          msg);
}
