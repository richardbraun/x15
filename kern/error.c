/*
 * Copyright (c) 2014-2017 Richard Braun.
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

const char *
error_str(int error)
{
    switch (error) {
    case 0:
        return "success";
    case ERROR_NOMEM:
        return "out of memory";
    case ERROR_AGAIN:
        return "resource temporarily unavailable";
    case ERROR_INVAL:
        return "invalid argument";
    case ERROR_BUSY:
        return "device or resource busy";
    case ERROR_FAULT:
        return "Bad address";
    case ERROR_NODEV:
        return "No such device";
    case ERROR_EXIST:
        return "Entry exists";
    case ERROR_IO:
        return "Input/output error";
    default:
        return "unknown error";
    }
}

void
error_check(int error, const char *prefix)
{
    if (!error) {
        return;
    }

    panic("%s%s%s",
          (prefix == NULL) ? "" : prefix,
          (prefix == NULL) ? "" : ": ",
          error_str(error));
}
