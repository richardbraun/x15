/*
 * Copyright (c) 2017-2019 Richard Braun.
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/bulletin.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
#include <kern/mbuf.h>
#include <kern/panic.h>
#include <kern/shell.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <machine/boot.h>
#include <machine/cpu.h>

#define LOG_BUFFER_SIZE 16384

#if !ISP2(LOG_BUFFER_SIZE)
#error "log buffer size must be a power-of-two"
#endif

#define LOG_MSG_SIZE 128

#define LOG_PRINT_LEVEL LOG_INFO

static struct thread *log_thread;

static struct mbuf log_mbuf;
static char log_buffer[LOG_BUFFER_SIZE];

static unsigned int log_nr_overruns;

static struct bulletin log_bulletin;

/*
 * Global lock.
 *
 * Interrupts must be disabled when holding this lock.
 */
static struct spinlock log_lock;

struct log_record {
    uint8_t level;
    char msg[LOG_MSG_SIZE];
};

struct log_consumer {
    struct mbuf *mbuf;
    size_t index;
};

static void
log_consumer_init(struct log_consumer *ctx, struct mbuf *mbuf)
{
    ctx->mbuf = mbuf;
    ctx->index = mbuf_start(mbuf);
}

static int
log_consumer_pop(struct log_consumer *ctx, struct log_record *record)
{
    size_t size;
    int error;

    for (;;) {
        size = sizeof(*record);
        error = mbuf_read(ctx->mbuf, &ctx->index, record, &size);

        if (error != EINVAL) {
            break;
        } else {
            ctx->index = mbuf_start(ctx->mbuf);
        }
    }

    return error;
}

static const char *
log_level2str(unsigned int level)
{
    switch (level) {
    case LOG_EMERG:
        return "emerg";
    case LOG_ALERT:
        return "alert";
    case LOG_CRIT:
        return "crit";
    case LOG_ERR:
        return "error";
    case LOG_WARNING:
        return "warning";
    case LOG_NOTICE:
        return "notice";
    case LOG_INFO:
        return "info";
    case LOG_DEBUG:
        return "debug";
    default:
        return NULL;
    }
}

static void
log_print_record(const struct log_record *record, unsigned int level)
{
    if (record->level > level) {
        return;
    }

    if (record->level <= LOG_WARNING) {
        printf("%7s %s\n", log_level2str(record->level), record->msg);
    } else {
        printf("%s\n", record->msg);
    }
}

static void
log_run(void *arg)
{
    struct log_consumer ctx;
    unsigned long flags;
    bool published;

    (void)arg;

    published = false;

    spinlock_lock_intr_save(&log_lock, &flags);

    log_consumer_init(&ctx, &log_mbuf);

    for (;;) {
        struct log_record record;

        for (;;) {
            int error;

            error = log_consumer_pop(&ctx, &record);

            if (!error) {
                break;
            } else if (log_nr_overruns != 0) {
                record.level = LOG_ERR;
                snprintf(record.msg, sizeof(record.msg),
                         "log: buffer overruns, %u messages dropped",
                         log_nr_overruns);
                log_nr_overruns = 0;
                break;
            }

            if (!published) {
                spinlock_unlock_intr_restore(&log_lock, flags);
                bulletin_publish(&log_bulletin, 0);
                spinlock_lock_intr_save(&log_lock, &flags);

                published = true;
            }

            thread_sleep(&log_lock, &log_mbuf, "log_mbuf");
        }

        spinlock_unlock_intr_restore(&log_lock, flags);

        log_print_record(&record, LOG_PRINT_LEVEL);

        spinlock_lock_intr_save(&log_lock, &flags);
    }
}

#ifdef CONFIG_SHELL

static void
log_dump(unsigned int level)
{
    struct log_consumer ctx;
    struct log_record record;
    unsigned long flags;
    int error;

    spinlock_lock_intr_save(&log_lock, &flags);

    log_consumer_init(&ctx, &log_mbuf);

    for (;;) {
        error = log_consumer_pop(&ctx, &record);

        if (error) {
            break;
        }

        spinlock_unlock_intr_restore(&log_lock, flags);

        log_print_record(&record, level);

        spinlock_lock_intr_save(&log_lock, &flags);
    }

    spinlock_unlock_intr_restore(&log_lock, flags);
}

static void
log_shell_dump(struct shell *shell, int argc, char **argv)
{
    unsigned int level;
    int ret;

    (void)shell;

    if (argc != 2) {
        level = LOG_PRINT_LEVEL;
    } else {
        ret = sscanf(argv[1], "%u", &level);

        if ((ret != 1) || (level >= LOG_NR_LEVELS)) {
            printf("log: dump: invalid arguments\n");
            return;
        }
    }

    log_dump(level);
}

static struct shell_cmd log_shell_cmds[] = {
    SHELL_CMD_INITIALIZER2("log_dump", log_shell_dump,
        "log_dump [<level>]",
        "dump the log buffer",
        "Only records of level less than or equal to the given level"
        " are printed. Level may be one of :\n"
        " 0: emergency\n"
        " 1: alert\n"
        " 2: critical\n"
        " 3: error\n"
        " 4: warning\n"
        " 5: notice\n"
        " 6: info\n"
        " 7: debug"),
};

static int __init
log_setup_shell(void)
{
    SHELL_REGISTER_CMDS(log_shell_cmds, shell_get_main_cmd_set());
    return 0;
}

INIT_OP_DEFINE(log_setup_shell,
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(shell_setup, true));

#endif /* CONFIG_SHELL */

static int __init
log_setup(void)
{
    mbuf_init(&log_mbuf, log_buffer, sizeof(log_buffer),
              sizeof(struct log_record));
    spinlock_init(&log_lock);
    bulletin_init(&log_bulletin);

    boot_log_info();
    arg_log_info();
    cpu_log_info(cpu_current());

    return 0;
}

INIT_OP_DEFINE(log_setup,
               INIT_OP_DEP(arg_setup, true),
               INIT_OP_DEP(cpu_setup, true),
               INIT_OP_DEP(spinlock_setup, true));

static int __init
log_start(void)
{
    struct thread_attr attr;
    int error;

    thread_attr_init(&attr, THREAD_KERNEL_PREFIX "log_run");
    thread_attr_set_detached(&attr);
    error = thread_create(&log_thread, &attr, log_run, NULL);

    if (error) {
        panic("log: unable to create thread");
    }

    return 0;
}

INIT_OP_DEFINE(log_start,
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(thread_setup, true));

int
log_msg(unsigned int level, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vmsg(level, format, ap);
    va_end(ap);

    return ret;
}

int
log_vmsg(unsigned int level, const char *format, va_list ap)
{
    struct log_record record;
    unsigned long flags;
    int error, nr_chars;
    size_t size;
    char *ptr;

    assert(level < LOG_NR_LEVELS);
    record.level = level;
    nr_chars = vsnprintf(record.msg, sizeof(record.msg), format, ap);

    if ((unsigned int)nr_chars >= sizeof(record.msg)) {
        log_msg(LOG_ERR, "log: message too large");
        goto out;
    }

    ptr = strchr(record.msg, '\n');

    if (ptr != NULL) {
        *ptr = '\0';
        nr_chars = ptr - record.msg;
    }

    assert(nr_chars >= 0);
    size = offsetof(struct log_record, msg) + nr_chars + 1;

    spinlock_lock_intr_save(&log_lock, &flags);

    error = mbuf_push(&log_mbuf, &record, size, true);

    if (error) {
        log_nr_overruns++;
    }

    thread_wakeup(log_thread);

    spinlock_unlock_intr_restore(&log_lock, flags);

out:
    return nr_chars;
}

int
log_emerg(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vemerg(format, ap);
    va_end(ap);

    return ret;
}

int
log_alert(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_valert(format, ap);
    va_end(ap);

    return ret;
}

int
log_crit(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vcrit(format, ap);
    va_end(ap);

    return ret;
}

int
log_err(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_verr(format, ap);
    va_end(ap);

    return ret;
}

int
log_warning(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vwarning(format, ap);
    va_end(ap);

    return ret;
}

int
log_notice(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vnotice(format, ap);
    va_end(ap);

    return ret;
}

int
log_info(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vinfo(format, ap);
    va_end(ap);

    return ret;
}

int
log_debug(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = log_vdebug(format, ap);
    va_end(ap);

    return ret;
}

int
log_vemerg(const char *format, va_list ap)
{
    return log_vmsg(LOG_EMERG, format, ap);
}

int
log_valert(const char *format, va_list ap)
{
    return log_vmsg(LOG_ALERT, format, ap);
}

int
log_vcrit(const char *format, va_list ap)
{
    return log_vmsg(LOG_CRIT, format, ap);
}

int
log_verr(const char *format, va_list ap)
{
    return log_vmsg(LOG_ERR, format, ap);
}

int
log_vwarning(const char *format, va_list ap)
{
    return log_vmsg(LOG_WARNING, format, ap);
}

int
log_vnotice(const char *format, va_list ap)
{
    return log_vmsg(LOG_NOTICE, format, ap);
}

int
log_vinfo(const char *format, va_list ap)
{
    return log_vmsg(LOG_INFO, format, ap);
}

int
log_vdebug(const char *format, va_list ap)
{
    return log_vmsg(LOG_DEBUG, format, ap);
}

struct bulletin *
log_get_bulletin(void)
{
    return &log_bulletin;
}
