/*
 * Priority Queue
 *
 * Copyright (c) 2022 Aerospike, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stdint.h>


//==========================================================
// Typedefs & constants.
//

typedef struct pq_entry {
	uint64_t priority;
	void* udata;
} pq_entry_t;

/*
 * Priority queue is implemented using a max binary-heap data structure.
 */
typedef struct priority_queue {
	pq_entry_t* buffer;
	uint64_t capacity;
	uint64_t size;
} priority_queue_t;


//==========================================================
// Public API.
//

/*
 * Initializes a priority queue with given initial capacity.
 */
int priority_queue_init(priority_queue_t*, uint64_t capacity);

void priority_queue_free(priority_queue_t*);

/*
 * Return the number of entries in the priority queue.
 */
uint64_t priority_queue_size(const priority_queue_t*);

/*
 * Pushes an item to the priority queue with given priority.
 *
 * Returns false if the item couldn't be pushed.
 */
bool priority_queue_push(priority_queue_t*, void* udata, uint64_t priority);

/*
 * Pops the highest priority item from the priority queue.
 */
void* priority_queue_pop(priority_queue_t*);

/*
 * Returns a pointer to the highest priority item entry without removing it from
 * the queue.
 *
 * This method has undefined behavior if the queue is empty.
 */
pq_entry_t priority_queue_peek(const priority_queue_t*);

