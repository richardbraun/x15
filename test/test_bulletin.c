/*
 * Copyright (c) 2018 Richard Braun.
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
 * This test makes a bulletin subscriber subscribe to a bulletin, and uses
 * a timer to periodically publish, unsubscribe, and resubscribe to the
 * bulletin. A counter is used to test passing values to the notification
 * callback function.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <kern/bulletin.h>
#include <kern/clock.h>
#include <kern/error.h>
#include <kern/log.h>
#include <kern/timer.h>
#include <test/test.h>

#define TEST_INTERVAL   1
#define TEST_NR_LOOPS   4

static struct bulletin test_bulletin;
static struct bulletin_sub test_bulletin_sub;
static struct timer test_timer;
static unsigned int test_counter;

static void
test_notify(uintptr_t value, void *arg)
{
    log_info("test: notify: value:%lu arg:%p", value, arg);
}

static void
test_tick(struct timer *timer)
{
    uint64_t ticks;

    test_counter++;
    bulletin_publish(&test_bulletin, test_counter);
    bulletin_unsubscribe(&test_bulletin, &test_bulletin_sub);

    if (test_counter == TEST_NR_LOOPS) {
        log_info("test: done");
        return;
    }

    bulletin_subscribe(&test_bulletin, &test_bulletin_sub,
                       test_notify, (void *)0x123);

    ticks = timer_get_time(timer) + clock_ticks_from_ms(TEST_INTERVAL * 1000);
    timer_schedule(&test_timer, ticks);
}

void __init
test_setup(void)
{
    uint64_t ticks;

    bulletin_init(&test_bulletin);
    bulletin_subscribe(&test_bulletin, &test_bulletin_sub,
                       test_notify, (void *)0x123);

    timer_init(&test_timer, test_tick, TIMER_DETACHED);
    ticks = clock_get_time() + clock_ticks_from_ms(TEST_INTERVAL * 1000);
    timer_schedule(&test_timer, ticks);
}
