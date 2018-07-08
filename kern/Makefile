x15_SOURCES-y += \
        kern/arg.c \
        kern/bitmap.c \
        kern/bulletin.c \
        kern/cbuf.c \
        kern/clock.c \
        kern/condition.c \
        kern/console.c \
        kern/cpumap.c \
        kern/error.c \
        kern/fmt.c \
        kern/init.c \
        kern/intr.c \
        kern/kernel.c \
        kern/kmem.c \
        kern/latomic.c \
        kern/log.c \
        kern/mutex.c \
        kern/panic.c \
        kern/percpu.c \
        kern/plist.c \
        kern/printf.c \
        kern/rbtree.c \
        kern/rcu.c \
        kern/rdxtree.c \
        kern/rtmutex.c \
        kern/semaphore.c \
        kern/shutdown.c \
        kern/sleepq.c \
        kern/spinlock.c \
        kern/sref.c \
        kern/string.c \
        kern/symbol.c \
        kern/syscnt.c \
        kern/task.c \
        kern/thread.c \
        kern/timer.c \
        kern/turnstile.c \
        kern/work.c \
        kern/xcall.c

x15_SOURCES-$(CONFIG_SHELL) += kern/shell.c

x15_SOURCES-$(CONFIG_MUTEX_ADAPTIVE) += kern/mutex/mutex_adaptive.c
x15_SOURCES-$(CONFIG_MUTEX_PLAIN) += kern/mutex/mutex_plain.c

x15_SOURCES-$(CONFIG_PERFMON) += kern/perfmon.c
