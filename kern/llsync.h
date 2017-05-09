/*
 * Copyright (c) 2013-2014 Richard Braun.
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
 * Lockless synchronization.
 *
 * The llsync module provides services similar to RCU (Read-Copy Update).
 * As such, it can be thought of as an efficient reader-writer lock
 * replacement. It is efficient because read-side critical sections
 * don't use expensive synchronization mechanisms such as locks or atomic
 * instructions. Lockless synchronization is therefore best used for
 * read-mostly objects. Updating still requires conventional lock-based
 * synchronization.
 *
 * The basic idea is that read-side critical sections are assumed to hold
 * read-side references, and objects for which there may be read-side
 * references must exist as long as such references may be held. The llsync
 * module tracks special system events to determine when read-side references
 * can no longer exist.
 *
 * Since read-side critical sections can run concurrently with updates,
 * it is important to make sure that objects are consistent when being
 * accessed. This is achieved with a publish/subscribe mechanism that relies
 * on the natural atomicity of machine word updates in memory, i.e. all
 * supported architectures must guarantee that, when updating a word, and
 * in turn a pointer, other processors reading that word obtain a valid
 * value, that is either the previous or the next value of the word, but not
 * a mixed-up value. The llsync module provides the llsync_assign_ptr() and
 * llsync_read_ptr() wrappers that take care of low level details such as
 * compiler and memory barriers, so that objects are completely built and
 * consistent when published and accessed.
 *
 * As objects are published through pointers, multiple versions can exist at
 * the same time. Previous versions cannot be deleted as long as read-side
 * references may exist. Operations that must wait for all read-side references
 * to be dropped can be either synchronous, i.e. block until it is safe to
 * proceed, or be deferred, in which case they are queued and later handed to
 * the work module. As a result, special care must be taken if using lockless
 * synchronization in the work module itself.
 *
 * The two system events tracked by the llsync module are context switches
 * and a periodic event, normally the periodic timer interrupt that drives
 * the scheduler. Context switches are used as checkpoint triggers. A
 * checkpoint is a point in execution at which no read-side reference can
 * exist, i.e. the processor isn't running any read-side critical section.
 * Since context switches can be very frequent, a checkpoint is local to
 * the processor and lightweight. The periodic event is used to commit
 * checkpoints globally so that other processors are aware of the progress
 * of one another. As the system allows situations in which two periodic
 * events can occur without a single context switch, the periodic event is
 * also used as a checkpoint trigger. When all checkpoints have been
 * committed, a global checkpoint occurs. The occurrence of global checkpoints
 * allows the llsync module to determine when it is safe to process deferred
 * work or unblock update sides.
 */

#ifndef _KERN_LLSYNC_H
#define _KERN_LLSYNC_H

#include <stdbool.h>

#include <kern/atomic.h>
#include <kern/macros.h>
#include <kern/llsync_i.h>
#include <kern/thread.h>
#include <kern/work.h>
#include <machine/mb.h>

/*
 * Safely assign a pointer.
 */
#define llsync_assign_ptr(ptr, value) atomic_store(&(ptr), value, ATOMIC_RELEASE)

/*
 * Safely access a pointer.
 */
#define llsync_read_ptr(ptr) atomic_load(&(ptr), ATOMIC_CONSUME)

/*
 * Read-side critical section enter/exit functions.
 *
 * It is not allowed to block inside a read-side critical section.
 */

static inline void
llsync_read_enter(void)
{
    int in_read_cs;

    in_read_cs = thread_llsync_in_read_cs();
    thread_llsync_read_inc();

    if (!in_read_cs) {
        thread_preempt_disable();
    }
}

static inline void
llsync_read_exit(void)
{
    thread_llsync_read_dec();

    if (!thread_llsync_in_read_cs()) {
        thread_preempt_enable();
    }
}

/*
 * Return true if the llsync module is initialized, false otherwise.
 */
bool llsync_ready(void);

/*
 * Initialize the llsync module.
 */
void llsync_setup(void);

/*
 * Manage registration of the current processor.
 *
 * The caller must not be allowed to migrate when calling these functions.
 *
 * Registering tells the llsync module that the current processor reports
 * context switches and periodic events.
 *
 * When a processor enters a state in which checking in becomes irrelevant,
 * it unregisters itself so that the other registered processors don't need
 * to wait for it to make progress. For example, this is done inside the
 * idle loop since it is obviously impossible to enter a read-side critical
 * section while idling.
 */
void llsync_register(void);
void llsync_unregister(void);

/*
 * Report a context switch on the current processor.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
static inline void
llsync_report_context_switch(void)
{
    llsync_checkin();
}

/*
 * Report a periodic event on the current processor.
 *
 * Interrupts and preemption must be disabled when calling this function.
 */
void llsync_report_periodic_event(void);

/*
 * Defer an operation until all existing read-side references are dropped,
 * without blocking.
 */
void llsync_defer(struct work *work);

/*
 * Wait for all existing read-side references to be dropped.
 *
 * This function sleeps, and may do so for a moderately long duration (a few
 * system timer ticks).
 */
void llsync_wait(void);

#endif /* _KERN_LLSYNC_H */
