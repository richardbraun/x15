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
 * Upstream site with license notes :
 * http://git.sceen.net/rbraun/librbraun.git/
 */

#include <kern/list.h>
#include <kern/plist.h>

void
plist_add(struct plist *plist, struct plist_node *pnode)
{
    struct plist_node *next;

    if (plist_empty(plist)) {
        list_insert_head(&plist->list, &pnode->node);
        list_insert_head(&plist->prio_list, &pnode->prio_node);
        return;
    }

    list_for_each_entry(&plist->prio_list, next, prio_node) {
        if (pnode->priority < next->priority) {
            break;
        }
    }

    if (list_end(&plist->prio_list, &next->prio_node)
        || (pnode->priority != next->priority)) {
        list_insert_before(&pnode->prio_node, &next->prio_node);
    } else {
        list_init(&pnode->prio_node);
    }

    list_insert_before(&pnode->node, &next->node);
}

void
plist_remove(struct plist *plist, struct plist_node *pnode)
{
    struct plist_node *next;

    if (!list_node_unlinked(&pnode->prio_node)) {
        next = list_next_entry(pnode, node);

        if (!list_end(&plist->list, &next->node)
            && list_node_unlinked(&next->prio_node)) {
            list_insert_after(&pnode->prio_node, &next->prio_node);
        }

        list_remove(&pnode->prio_node);
    }

    list_remove(&pnode->node);
}
