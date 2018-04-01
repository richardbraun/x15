/*
 * Copyright (c) 2017-2018 Richard Braun.
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
 * Minimalist publish-subscribe mechanism.
 */

#ifndef KERN_BULLETIN_H
#define KERN_BULLETIN_H

#include <stdint.h>

#include <kern/macros.h>
#include <kern/work.h>

/*
 * Type for bulletin notification functions.
 *
 * The value is passed from the publisher unmodified, and can safely be
 * cast into a pointer. Notification functions run in the context of the
 * publisher.
 */
typedef void (*bulletin_notif_fn_t)(uintptr_t value, void *arg);

#include <kern/bulletin_i.h>

struct bulletin;

/*
 * Bulletin subscriber.
 */
struct bulletin_sub;

void bulletin_init(struct bulletin *bulletin);

/*
 * Subscribe to a bulletin.
 *
 * Once subscribed, the notification function is called with its argument
 * each time the bulletin is published.
 */
void bulletin_subscribe(struct bulletin *bulletin, struct bulletin_sub *sub,
                        bulletin_notif_fn_t notif_fn, void *arg);

/*
 * Unsubscribe from a bulletin.
 *
 * On return, the subscriber notification function may not be called any more.
 *
 * This function synchronizes with RCU.
 */
void bulletin_unsubscribe(struct bulletin *bulletin, struct bulletin_sub *sub);

/*
 * Publish a bulletin.
 *
 * All subscribers are notified by calling their notification function, with
 * the given value passed unmodified.
 */
void bulletin_publish(struct bulletin *bulletin, uintptr_t value);

#endif /* KERN_BULLETIN_H */
