/*
 * Copyright (c) 2012 Richard Braun.
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

#include <kern/param.h>
#include <machine/tcb.h>

/*
 * Low level context switch function.
 */
void tcb_context_switch(struct tcb *prev, struct tcb *next);

void
tcb_init(struct tcb *tcb, void *stack, void (*fn)(void))
{
    tcb->sp = (unsigned long)stack + STACK_SIZE;
    tcb->ip = (unsigned long)fn;
}

void tcb_switch(struct tcb *prev, struct tcb *next)
{
    tcb_context_switch(prev, next);
}
