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
 * This implementation is based on "Solaris(tm) Internals: Solaris 10 and
 * OpenSolaris Kernel Architecture, Second Edition" by Richard McDougall
 * and Jim Mauro. See "Part Six: Platform Specifics, Chapter 17: Locking
 * and Synchronization, Section 7 Turnstiles and Priority Inheritance".
 *
 * The differences are outlined below.
 *
 * This implementation doesn't support read/write locks, only mutual
 * exclusion, because ownership doesn't apply well to read/write locks.
 *
 * Instead of using an external sleep queue object, this module implements
 * that functionality itself. The reasons behind this decision are :
 *  - the use of expensive priority lists used to queue threads, that
 *    a simpler sleep queue implementation shouldn't use
 *  - increased coupling with the scheduler
 *
 * Locking order : bucket (turnstile) -> turnstile_td -> thread_runq
 *
 * This order allows changing the owner of a turnstile without unlocking it
 * which is important because a turnstile is normally used to synchronize
 * access to the owner. Unlocking a turnstile would allow the owner to
 * change and make complex transient states visible. The drawback is that
 * a thread cannot be requeued atomically when its priority is changed.
 * That deferred requeue is done during priority propagation.
 *
 * TODO Analyse hash parameters.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <kern/assert.h>
#include <kern/init.h>
#include <kern/kmem.h>
#include <kern/list.h>
#include <kern/macros.h>
#include <kern/param.h>
#include <kern/plist.h>
#include <kern/spinlock.h>
#include <kern/thread.h>
#include <kern/turnstile.h>
#include <kern/turnstile_types.h>

/*
 * Locking keys :
 * (b) bucket
 */
struct turnstile_bucket {
    struct spinlock lock;
    struct list list;       /* (b) */
} __aligned(CPU_L1_SIZE);

/*
 * Adding/removing waiters to/from a turnstile are performed while
 * holding both the waiter's thread data and the turnstile locks.
 *
 * Changing the owner of a turnstile and linking/unlinking the turnstile
 * into/from the owner's list of owned turnstiles are done atomically,
 * while holding both the owner's thread data and the turnstile locks.
 *
 * Locking keys :
 * (b) bucket
 * (t) turnstile_td
 *
 * (*) A turnstile is referenced in thread data after/before being
 * added/removed to/from its bucket. Referencing a turnstile in
 * thread data requires holding the thread data lock. This implies
 * that, while holding the thread data lock, if the referenced
 * turnstile isn't NULL, the bucket pointer is also not NULL and
 * stable.
 */
struct turnstile {
    struct turnstile_bucket *bucket;        /* (b*)  */
    struct list node;                       /* (b)   */
    const void *sync_obj;                   /* (b)   */
    struct plist waiters;                   /* (b,t) */
    struct turnstile *next_free;            /* (b)   */
    struct turnstile_waiter *top_waiter;    /* (b,t) */
    struct thread *owner;                   /* (b,t) */
    struct plist_node td_node;              /* (t)   */
};

/*
 * Locking keys :
 * (b) bucket
 * (t) turnstile_td
 */
struct turnstile_waiter {
    struct plist_node node; /* (b,t) */
    struct thread *thread;  /* (b,t) */
    bool awaken;            /* (b)   */
};

#define TURNSTILE_HTABLE_SIZE 128

#if !ISP2(TURNSTILE_HTABLE_SIZE)
#error hash table size must be a power of two
#endif /* !ISP2(TURNSTILE_HTABLE_SIZE) */

#define TURNSTILE_HTABLE_MASK (TURNSTILE_HTABLE_SIZE - 1)

static struct turnstile_bucket turnstile_htable[TURNSTILE_HTABLE_SIZE];

static struct kmem_cache turnstile_cache;

static uintptr_t
turnstile_hash(const void *addr)
{
    return ((uintptr_t)addr >> 8) ^ (uintptr_t)addr;
}

static void
turnstile_waiter_init(struct turnstile_waiter *waiter, struct thread *thread)
{
    plist_node_init(&waiter->node, thread_real_global_priority(thread));
    waiter->thread = thread;
    waiter->awaken = false;
}

static unsigned int
turnstile_waiter_priority(const struct turnstile_waiter *waiter)
{
    return plist_node_priority(&waiter->node);
}

static bool
turnstile_waiter_awaken(const struct turnstile_waiter *waiter)
{
    return waiter->awaken;
}

static void
turnstile_waiter_set_awaken(struct turnstile_waiter *waiter)
{
    waiter->awaken = true;
}

static void
turnstile_waiter_clear_awaken(struct turnstile_waiter *waiter)
{
    waiter->awaken = false;
}

static void
turnstile_waiter_wakeup(struct turnstile_waiter *waiter)
{
    if (turnstile_waiter_awaken(waiter)) {
        return;
    }

    thread_wakeup(waiter->thread);
    turnstile_waiter_set_awaken(waiter);
}

static void
turnstile_update_top_waiter(struct turnstile *turnstile)
{
    if (turnstile_empty(turnstile)) {
        turnstile->top_waiter = NULL;
        return;
    }

    turnstile->top_waiter = plist_last_entry(&turnstile->waiters,
                                             struct turnstile_waiter, node);
}

static void
turnstile_add_waiter(struct turnstile *turnstile,
                     struct turnstile_waiter *waiter)
{
    assert(!turnstile_waiter_awaken(waiter));
    plist_add(&turnstile->waiters, &waiter->node);
    turnstile_update_top_waiter(turnstile);
}

static void
turnstile_remove_waiter(struct turnstile *turnstile,
                        struct turnstile_waiter *waiter)
{
    assert(turnstile_waiter_awaken(waiter));
    plist_remove(&turnstile->waiters, &waiter->node);
    turnstile_update_top_waiter(turnstile);
}

static void
turnstile_waiter_requeue(struct turnstile *turnstile,
                         struct turnstile_waiter *waiter)
{
    unsigned int global_priority;

    global_priority = thread_real_global_priority(waiter->thread);
    assert(global_priority != plist_node_priority(&waiter->node));

    plist_remove(&turnstile->waiters, &waiter->node);
    plist_node_set_priority(&waiter->node, global_priority);
    plist_add(&turnstile->waiters, &waiter->node);
    turnstile_update_top_waiter(turnstile);
}

static void
turnstile_td_set_waiter(struct turnstile_td *td,
                        struct turnstile_waiter *waiter)
{
    td->waiter = waiter;
}

static struct turnstile_waiter *
turnstile_td_get_waiter(const struct turnstile_td *td)
{
    return td->waiter;
}

static void
turnstile_td_update_top_priority(struct turnstile_td *td)
{
    struct turnstile_waiter *top_waiter;
    struct turnstile *top_turnstile;

    if (plist_empty(&td->owned_turnstiles)) {
        td->top_global_priority = 0;
        return;
    }

    top_turnstile = plist_last_entry(&td->owned_turnstiles,
                                     struct turnstile, td_node);
    top_waiter = top_turnstile->top_waiter;

    if (top_waiter == NULL) {
        td->top_global_priority = 0;
    } else {
        td->top_global_priority = turnstile_waiter_priority(top_waiter);
        td->top_sched_policy = thread_real_sched_policy(top_waiter->thread);
        td->top_priority = thread_real_priority(top_waiter->thread);
    }
}

static void
turnstile_td_own(struct turnstile_td *td, struct turnstile *turnstile)
{
    struct turnstile_waiter *top_waiter;
    unsigned int top_priority;

    assert(turnstile->owner == NULL);

    top_waiter = turnstile->top_waiter;
    assert(top_waiter != NULL);
    top_priority = thread_real_global_priority(top_waiter->thread);
    plist_node_init(&turnstile->td_node, top_priority);
    plist_add(&td->owned_turnstiles, &turnstile->td_node);
    turnstile_td_update_top_priority(td);

    turnstile->owner = structof(td, struct thread, turnstile_td);
}

static void
turnstile_td_disown(struct turnstile_td *td, struct turnstile *turnstile)
{
    assert(turnstile->owner == structof(td, struct thread, turnstile_td));

    assert(!plist_node_unlinked(&turnstile->td_node));
    plist_remove(&td->owned_turnstiles, &turnstile->td_node);
    turnstile_td_update_top_priority(td);

    turnstile->owner = NULL;
}

static void
turnstile_td_reown(struct turnstile_td *td, struct turnstile *turnstile)
{
    assert(turnstile->owner == structof(td, struct thread, turnstile_td));
    assert(!plist_node_unlinked(&turnstile->td_node));
    plist_remove(&td->owned_turnstiles, &turnstile->td_node);
    turnstile->owner = NULL;
    turnstile_td_own(td, turnstile);
}

/*
 * The caller must hold the turnstile thread data lock and no turnstile
 * locks when calling this function. The thread data are unlocked on return.
 *
 * In addition, this function drops a reference on the thread associated
 * with the given thread data.
 */
static void
turnstile_td_propagate_priority_loop(struct turnstile_td *td)
{
    unsigned int user_priority, real_priority, top_priority;
    struct turnstile_waiter *waiter;
    struct turnstile *turnstile;
    struct thread *thread;
    unsigned short priority;
    unsigned char policy;
    int error;

    /*
     * At the very least, this function must make sure that :
     *  - the given thread has its intended priority, which is the
     *    highest among its own and all the waiters in the turnstiles
     *    it owns, and
     *  - the thread is at its intended position in the turnstile it's
     *    waiting on, if any.
     */

    for (;;) {
        thread = structof(td, struct thread, turnstile_td);
        user_priority = thread_user_global_priority(thread);
        real_priority = thread_real_global_priority(thread);
        top_priority = td->top_global_priority;

        if (top_priority > user_priority) {
            policy = td->top_sched_policy;
            priority = td->top_priority;
        } else {
            top_priority = user_priority;
            policy = thread_user_sched_policy(thread);
            priority = thread_user_priority(thread);
        }

        if (top_priority != real_priority) {
            thread_pi_setscheduler(thread, policy, priority);
        }

        waiter = turnstile_td_get_waiter(td);

        if ((waiter == NULL)
            || (top_priority == turnstile_waiter_priority(waiter))) {
            spinlock_unlock(&td->lock);
            thread_unref(thread);
            return;
        }

        turnstile = turnstile_td_get_turnstile(td);
        assert(turnstile != NULL);

        error = spinlock_trylock(&turnstile->bucket->lock);

        if (error) {
            spinlock_unlock(&td->lock);
            spinlock_lock(&td->lock);
            continue;
        }

        /*
         * This couldn't be done while changing the thread's priority
         * because of locking restrictions. Do it now.
         */
        turnstile_waiter_requeue(turnstile, waiter);

        spinlock_unlock(&td->lock);
        thread_unref(thread);

        thread = turnstile->owner;

        if (thread == NULL) {
            break;
        }

        td = thread_turnstile_td(thread);

        thread_ref(thread);
        spinlock_lock(&td->lock);

        turnstile_td_reown(td, turnstile);

        spinlock_unlock(&turnstile->bucket->lock);
    }

    spinlock_unlock(&turnstile->bucket->lock);
}

void
turnstile_td_propagate_priority(struct turnstile_td *td)
{
    struct thread *thread;

    thread = structof(td, struct thread, turnstile_td);

    thread_ref(thread);
    spinlock_lock(&td->lock);
    turnstile_td_propagate_priority_loop(td);
}

static void
turnstile_assert_init_state(const struct turnstile *turnstile)
{
    assert(turnstile->bucket == NULL);
    assert(turnstile->sync_obj == NULL);
    assert(plist_empty(&turnstile->waiters));
    assert(turnstile->next_free == NULL);
    assert(turnstile->top_waiter == NULL);
    assert(turnstile->owner == NULL);
}

static void
turnstile_use(struct turnstile *turnstile, const void *sync_obj)
{
    assert(turnstile->sync_obj == NULL);
    turnstile->sync_obj = sync_obj;
}

static void
turnstile_unuse(struct turnstile *turnstile)
{
    assert(turnstile->sync_obj != NULL);
    turnstile->sync_obj = NULL;
}

static bool
turnstile_in_use(const struct turnstile *turnstile)
{
    return turnstile->sync_obj != NULL;
}

static bool
turnstile_in_use_by(const struct turnstile *turnstile, const void *sync_obj)
{
    return turnstile->sync_obj == sync_obj;
}

static void
turnstile_bucket_init(struct turnstile_bucket *bucket)
{
    spinlock_init(&bucket->lock);
    list_init(&bucket->list);
}

static struct turnstile_bucket *
turnstile_bucket_get(const void *sync_obj)
{
    uintptr_t index;

    index = turnstile_hash(sync_obj) & TURNSTILE_HTABLE_MASK;
    assert(index < ARRAY_SIZE(turnstile_htable));
    return &turnstile_htable[index];
}

static void
turnstile_bucket_add(struct turnstile_bucket *bucket,
                     struct turnstile *turnstile)
{
    assert(turnstile->bucket == NULL);
    turnstile->bucket = bucket;
    list_insert_tail(&bucket->list, &turnstile->node);
}

static void
turnstile_bucket_remove(struct turnstile_bucket *bucket,
                        struct turnstile *turnstile)
{
    assert(turnstile->bucket == bucket);
    turnstile->bucket = NULL;
    list_remove(&turnstile->node);
}

static struct turnstile *
turnstile_bucket_lookup(const struct turnstile_bucket *bucket,
                        const void *sync_obj)
{
    struct turnstile *turnstile;

    list_for_each_entry(&bucket->list, turnstile, node) {
        if (turnstile_in_use_by(turnstile, sync_obj)) {
            return turnstile;
        }
    }

    return NULL;
}

static void
turnstile_ctor(void *ptr)
{
    struct turnstile *turnstile;

    turnstile = ptr;
    turnstile->bucket = NULL;
    turnstile->sync_obj = NULL;
    plist_init(&turnstile->waiters);
    turnstile->next_free = NULL;
    turnstile->top_waiter = NULL;
    turnstile->owner = NULL;
}

void __init
turnstile_bootstrap(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(turnstile_htable); i++) {
        turnstile_bucket_init(&turnstile_htable[i]);
    }
}

void __init
turnstile_setup(void)
{
    kmem_cache_init(&turnstile_cache, "turnstile", sizeof(struct turnstile),
                    CPU_L1_SIZE, turnstile_ctor, 0);
}

struct turnstile *
turnstile_create(void)
{
    struct turnstile *turnstile;

    turnstile = kmem_cache_alloc(&turnstile_cache);

    if (turnstile == NULL) {
        return NULL;
    }

    turnstile_assert_init_state(turnstile);
    return turnstile;
}

void
turnstile_destroy(struct turnstile *turnstile)
{
    turnstile_assert_init_state(turnstile);
    kmem_cache_free(&turnstile_cache, turnstile);
}

struct turnstile *
turnstile_acquire(const void *sync_obj)
{
    struct turnstile_bucket *bucket;
    struct turnstile *turnstile;

    assert(sync_obj != NULL);

    bucket = turnstile_bucket_get(sync_obj);

    spinlock_lock(&bucket->lock);

    turnstile = turnstile_bucket_lookup(bucket, sync_obj);

    if (turnstile == NULL) {
        spinlock_unlock(&bucket->lock);
        return NULL;
    }

    return turnstile;
}

void
turnstile_release(struct turnstile *turnstile)
{
    spinlock_unlock(&turnstile->bucket->lock);
}

static void
turnstile_push_free(struct turnstile *turnstile,
                    struct turnstile *free_turnstile)
{
    assert(free_turnstile->next_free == NULL);
    free_turnstile->next_free = turnstile->next_free;
    turnstile->next_free = free_turnstile;
}

static struct turnstile *
turnstile_pop_free(struct turnstile *turnstile)
{
    struct turnstile *free_turnstile;

    free_turnstile = turnstile->next_free;

    if (free_turnstile == NULL) {
        return NULL;
    }

    turnstile->next_free = free_turnstile->next_free;
    free_turnstile->next_free = NULL;
    return free_turnstile;
}

struct turnstile *
turnstile_lend(const void *sync_obj)
{
    struct turnstile_bucket *bucket;
    struct turnstile *turnstile, *prev;
    struct turnstile_td *td;

    assert(sync_obj != NULL);

    turnstile = thread_turnstile_lend();
    turnstile_assert_init_state(turnstile);

    td = thread_turnstile_td(thread_self());
    bucket = turnstile_bucket_get(sync_obj);

    spinlock_lock(&bucket->lock);

    prev = turnstile_bucket_lookup(bucket, sync_obj);

    if (prev == NULL) {
        turnstile_use(turnstile, sync_obj);
        turnstile_bucket_add(bucket, turnstile);
    } else {
        turnstile_push_free(prev, turnstile);
        turnstile = prev;
    }

    spinlock_lock(&td->lock);
    turnstile_td_set_turnstile(td, turnstile);
    spinlock_unlock(&td->lock);

    return turnstile;
}

void
turnstile_return(struct turnstile *turnstile)
{
    struct turnstile_bucket *bucket;
    struct turnstile *free_turnstile;
    struct turnstile_td *td;

    assert(turnstile_in_use(turnstile));

    td = thread_turnstile_td(thread_self());

    spinlock_lock(&td->lock);
    turnstile_td_set_turnstile(td, NULL);
    spinlock_unlock(&td->lock);

    bucket = turnstile->bucket;
    free_turnstile = turnstile_pop_free(turnstile);

    if (free_turnstile == NULL) {
        turnstile_bucket_remove(bucket, turnstile);
        turnstile_unuse(turnstile);
        free_turnstile = turnstile;
    }

    spinlock_unlock(&bucket->lock);

    turnstile_assert_init_state(free_turnstile);
    thread_turnstile_return(free_turnstile);
}

bool
turnstile_empty(const struct turnstile *turnstile)
{
    return plist_empty(&turnstile->waiters);
}

static void
turnstile_set_owner(struct turnstile *turnstile, struct thread *owner)
{
    struct turnstile_td *td;

    assert(owner != NULL);
    assert((turnstile->owner == NULL) || (turnstile->owner == owner));

    td = thread_turnstile_td(owner);

    thread_ref(owner);
    spinlock_lock(&td->lock);

    if (turnstile->owner == NULL) {
        turnstile_td_own(td, turnstile);
    }

    spinlock_unlock(&turnstile->bucket->lock);

    turnstile_td_propagate_priority_loop(td);

    spinlock_lock(&turnstile->bucket->lock);
}

void
turnstile_wait(struct turnstile *turnstile, const char *wchan,
               struct thread *owner)
{
    struct turnstile_waiter waiter;
    struct turnstile_td *td;
    struct thread *thread;

    thread = thread_self();
    assert(thread != owner);

    td = thread_turnstile_td(thread);

    spinlock_lock(&td->lock);
    turnstile_waiter_init(&waiter, thread);
    turnstile_add_waiter(turnstile, &waiter);
    turnstile_td_set_waiter(td, &waiter);
    spinlock_unlock(&td->lock);

    if (owner == NULL) {
        if (turnstile->top_waiter == &waiter) {
            turnstile_waiter_set_awaken(&waiter);
        }
    } else {
        /* This function temporarily unlocks the turnstile */
        turnstile_set_owner(turnstile, owner);
    }

    for (;;) {
        if (!turnstile_waiter_awaken(&waiter)) {
            thread_sleep(&turnstile->bucket->lock, turnstile->sync_obj, wchan);
        }

        /*
         * The real priority of a thread may change between waking up
         * and reacquiring the turnstile.
         */
        if (turnstile->top_waiter == &waiter) {
            break;
        }

        /* Otherwise, make sure the new top waiter is awaken */
        turnstile_waiter_wakeup(turnstile->top_waiter);
        turnstile_waiter_clear_awaken(&waiter);
    }

    spinlock_lock(&td->lock);
    turnstile_td_set_waiter(td, NULL);
    turnstile_remove_waiter(turnstile, &waiter);
    spinlock_unlock(&td->lock);
}

void
turnstile_signal(struct turnstile *turnstile)
{
    struct turnstile_waiter *waiter;

    if (turnstile_empty(turnstile)) {
        return;
    }

    waiter = plist_last_entry(&turnstile->waiters,
                              struct turnstile_waiter, node);
    turnstile_waiter_wakeup(waiter);
}

void
turnstile_own(struct turnstile *turnstile)
{
    struct turnstile_td *td;
    struct thread *owner;
    unsigned int top_priority;

    assert(turnstile->owner == NULL);

    if (turnstile_empty(turnstile)) {
        return;
    }

    owner = thread_self();
    top_priority = turnstile_waiter_priority(turnstile->top_waiter);
    assert(thread_real_global_priority(owner) >= top_priority);
    td = thread_turnstile_td(owner);

    spinlock_lock(&td->lock);
    turnstile_td_own(td, turnstile);
    spinlock_unlock(&td->lock);
}

void
turnstile_disown(struct turnstile *turnstile)
{
    struct turnstile_td *td;
    struct thread *owner;

    owner = thread_self();
    assert(turnstile->owner == owner);
    assert(!turnstile_empty(turnstile));

    td = thread_turnstile_td(owner);

    spinlock_lock(&td->lock);
    turnstile_td_disown(td, turnstile);
    spinlock_unlock(&td->lock);
}
