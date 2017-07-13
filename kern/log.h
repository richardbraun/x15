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
 * System logging.
 */

#ifndef _KERN_LOG_H
#define _KERN_LOG_H

#include <stdarg.h>


#include <kern/init.h>
enum {
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
    LOG_NR_LEVELS,
};

/*
 * Generate a message and send it to the log thread.
 *
 * The arguments and return value are similar to printf(), with
 * these exceptions :
 *  - a level is associated to each log message
 *  - processing stops at the first terminating null byte or newline
 *    character, whichever occurs first
 *
 * This function may safely be called in interrupt context.
 */
int log_msg(unsigned int level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

int log_vmsg(unsigned int level, const char *format, va_list ap)
    __attribute__((format(printf, 2, 0)));

/*
 * Convenience wrappers.
 */

int log_emerg(const char *format, ...) __attribute__((format(printf, 1, 2)));
int log_alert(const char *format, ...) __attribute__((format(printf, 1, 2)));
int log_crit(const char *format, ...) __attribute__((format(printf, 1, 2)));
int log_err(const char *format, ...) __attribute__((format(printf, 1, 2)));
int log_warning(const char *format, ...) __attribute__((format(printf, 1, 2)));
int log_notice(const char *format, ...) __attribute__((format(printf, 1, 2)));
int log_info(const char *format, ...) __attribute__((format(printf, 1, 2)));
int log_debug(const char *format, ...) __attribute__((format(printf, 1, 2)));

int log_vemerg(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));
int log_valert(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));
int log_vcrit(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));
int log_verr(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));
int log_vwarning(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));
int log_vnotice(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));
int log_vinfo(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));
int log_vdebug(const char *format, va_list ap)
    __attribute__((format(printf, 1, 0)));

/*
 * This init operation provides :
 *  - message logging
 *
 * The log thread isn't yet started and messages are merely stored in an
 * internal buffer.
 */
INIT_OP_DECLARE(log_setup);

#endif /* _KERN_LOG_H */
