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
 */

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <kern/arg.h>
#include <kern/cbuf.h>
#include <kern/init.h>
#include <kern/log.h>
#include <kern/macros.h>
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

#define LOG_MARKER 0x1

static struct thread *log_thread;

static struct cbuf log_cbuf;
static char log_buffer[LOG_BUFFER_SIZE];

/*
 * This index is used by the log thread to report what it has consumed
 * so that producers can detect overruns.
 */
static size_t log_index;

static size_t log_nr_overruns;

static unsigned int log_print_level;

/*
 * Global lock.
 *
 * Interrupts must be disabled when holding this lock.
 */
static struct spinlock log_lock;

/*
 * A record starts with a marker byte and ends with a null terminating byte.
 *
 * There must be no null byte inside the header, and the buffer is expected
 * to be a standard null-terminated string.
 */
struct log_record {
    uint8_t mark;
    uint8_t level;
    char buffer[LOG_MSG_SIZE];
};

/*
 * A consumer context allows faster, buffered reads of the circular buffer,
 * by retaining bytes that weren't consumed in case a read spans multiple
 * records.
 */
struct log_consume_ctx {
    struct cbuf *cbuf;
    size_t cbuf_index;
    char buf[LOG_MSG_SIZE];
    size_t index;
    size_t size;
};

static void
log_consume_ctx_init(struct log_consume_ctx *ctx, struct cbuf *cbuf)
{
    ctx->cbuf = cbuf;
    ctx->cbuf_index = cbuf_start(cbuf);
    ctx->index = 0;
    ctx->size = 0;
}

static size_t
log_consume_ctx_index(const struct log_consume_ctx *ctx)
{
    return ctx->cbuf_index;
}

static void
log_consume_ctx_set_index(struct log_consume_ctx *ctx, size_t index)
{
    ctx->cbuf_index = index;
}

static bool
log_consume_ctx_empty(const struct log_consume_ctx *ctx)
{
    return ctx->cbuf_index == cbuf_end(ctx->cbuf);
}

static int
log_consume_ctx_pop(struct log_consume_ctx *ctx, char *byte)
{
    int error;

    if (ctx->index >= ctx->size) {
        ctx->index = 0;
        ctx->size = sizeof(ctx->buf);
        error = cbuf_read(ctx->cbuf, ctx->cbuf_index, ctx->buf, &ctx->size);

        if (error) {
            ctx->cbuf_index = cbuf_start(ctx->cbuf);
            return error;
        }
    }

    ctx->cbuf_index++;
    *byte = ctx->buf[ctx->index];
    ctx->index++;
    return 0;
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

static char
log_level2char(unsigned int level)
{
    assert(level < LOG_NR_LEVELS);
    return '0' + level;
}

static uint8_t
log_char2level(char c)
{
    uint8_t level;

    level = c - '0';
    assert(level < LOG_NR_LEVELS);
    return level;
}

static void
log_record_init_produce(struct log_record *record, unsigned int level)
{
    record->mark = LOG_MARKER;
    record->level = log_level2char(level);
}

static void
log_record_consume(struct log_record *record, char c, size_t *sizep)
{
    char *ptr;

    assert(*sizep < sizeof(*record));

    ptr = (char *)record;
    ptr[*sizep] = c;
    (*sizep)++;
}

static int
log_record_init_consume(struct log_record *record, struct log_consume_ctx *ctx)
{
    bool marker_found;
    size_t size;
    int error;
    char c;

    marker_found = false;
    size = 0;

    for (;;) {
        if (log_consume_ctx_empty(ctx)) {
            if (!marker_found) {
                return ERROR_INVAL;
            }

            break;
        }

        error = log_consume_ctx_pop(ctx, &c);

        if (error) {
            continue;
        }

        if (!marker_found) {
            if (c != LOG_MARKER) {
                continue;
            }

            marker_found = true;
            log_record_consume(record, c, &size);
            continue;
        } else if (size == offsetof(struct log_record, level)) {
            record->level = log_char2level(c);
            size++;
            continue;
        }

        log_record_consume(record, c, &size);

        if (c == '\0') {
            break;
        }
    }

    return 0;
}

static void
log_record_print(const struct log_record *record, unsigned int level)
{
    if (record->level > level) {
        return;
    }

    if (record->level <= LOG_WARNING) {
        printf("%7s %s\n", log_level2str(record->level), record->buffer);
    } else {
        printf("%s\n", record->buffer);
    }
}

static void
log_run(void *arg)
{
    unsigned long flags, nr_overruns;
    struct log_consume_ctx ctx;
    struct log_record record;
    bool start_shell;
    int error;

    (void)arg;

    nr_overruns = 0;
    start_shell = true;

    spinlock_lock_intr_save(&log_lock, &flags);

    log_consume_ctx_init(&ctx, &log_cbuf);

    for (;;) {
        while (log_consume_ctx_empty(&ctx)) {
            /*
             * Starting the shell after the log thread sleeps for the first
             * time cleanly serializes log messages and shell prompt, making
             * a clean ordered output.
             */
            if (start_shell) {
                spinlock_unlock_intr_restore(&log_lock, flags);
                shell_start();
                start_shell = false;
                spinlock_lock_intr_save(&log_lock, &flags);
            }

            log_index = log_consume_ctx_index(&ctx);

            thread_sleep(&log_lock, &log_cbuf, "log_cbuf");

            log_consume_ctx_set_index(&ctx, log_index);
        }

        error = log_record_init_consume(&record, &ctx);

        /* Drain the log buffer before reporting overruns */
        if (log_consume_ctx_empty(&ctx)) {
            nr_overruns = log_nr_overruns;
            log_nr_overruns = 0;
        }

        log_index = log_consume_ctx_index(&ctx);

        spinlock_unlock_intr_restore(&log_lock, flags);

        if (!error) {
            log_record_print(&record, log_print_level);
        }

        if (nr_overruns != 0) {
            log_msg(LOG_ERR, "log: buffer overruns, %lu bytes dropped",
                    nr_overruns);
            nr_overruns = 0;
        }

        spinlock_lock_intr_save(&log_lock, &flags);

        log_consume_ctx_set_index(&ctx, log_index);
    }
}

#ifdef X15_ENABLE_SHELL

static void
log_dump(unsigned int level)
{
    struct log_consume_ctx ctx;
    struct log_record record;
    unsigned long flags;
    int error;

    spinlock_lock_intr_save(&log_lock, &flags);

    log_consume_ctx_init(&ctx, &log_cbuf);

    for (;;) {
        error = log_record_init_consume(&record, &ctx);

        if (error) {
            break;
        }

        spinlock_unlock_intr_restore(&log_lock, flags);

        log_record_print(&record, level);

        spinlock_lock_intr_save(&log_lock, &flags);
    }

    spinlock_unlock_intr_restore(&log_lock, flags);
}

static void
log_shell_dump(int argc, char **argv)
{
    unsigned int level;
    int ret;

    if (argc != 2) {
        level = log_print_level;
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
    SHELL_REGISTER_CMDS(log_shell_cmds);
    return 0;
}

INIT_OP_DEFINE(log_setup_shell,
               INIT_OP_DEP(log_setup, true),
               INIT_OP_DEP(shell_setup, true));

#endif /* X15_ENABLE_SHELL */

static int __init
log_setup(void)
{
    cbuf_init(&log_cbuf, log_buffer, sizeof(log_buffer));
    log_index = cbuf_start(&log_cbuf);
    spinlock_init(&log_lock);
    log_print_level = LOG_INFO;

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
               INIT_OP_DEP(panic_setup, true),
               INIT_OP_DEP(thread_setup, true));

static void
log_write(const void *s, size_t size)
{
    __unused int error;

    error = cbuf_push(&log_cbuf, s, size, true);
    assert(!error);

    if (!cbuf_range_valid(&log_cbuf, log_index, log_index + 1)) {
        log_nr_overruns += cbuf_start(&log_cbuf) - log_index;
        log_index = cbuf_start(&log_cbuf);
    }
}

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
    int nr_chars;
    size_t size;
    char *ptr;

    log_record_init_produce(&record, level);
    nr_chars = vsnprintf(record.buffer, sizeof(record.buffer), format, ap);

    if ((unsigned int)nr_chars >= sizeof(record.buffer)) {
        log_msg(LOG_ERR, "log: message too large");
        goto out;
    }

    ptr = strchr(record.buffer, '\n');

    if (ptr != NULL) {
        *ptr = '\0';
        nr_chars = ptr - record.buffer;
    }

    assert(nr_chars >= 0);
    size = offsetof(struct log_record, buffer) + nr_chars + 1;

    spinlock_lock_intr_save(&log_lock, &flags);
    log_write(&record, size);
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
