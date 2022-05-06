/*
 * Copyright 2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

//==========================================================
// Includes.
//

#include <priority_queue.h>

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <citrusleaf/alloc.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"


//==========================================================
// Public API.
//

int
priority_queue_init(priority_queue_t* pq, uint64_t capacity)
{
	pq->buffer = (pq_entry_t*) cf_malloc(capacity * sizeof(pq_entry_t));
	pq->capacity = capacity;
	pq->size = 0;

	return 0;
}

void
priority_queue_free(priority_queue_t* pq)
{
	cf_free(pq->buffer);
}

bool
priority_queue_push(priority_queue_t* pq, void* udata, uint64_t priority)
{
	uint64_t size = pq->size;

	if (size == pq->capacity) {
		return false;
	}

	while (size > 0) {
		// Heap is laid out so a node at index i has children at 2*i + 1 and 2*i + 2
		uint64_t parent = (size - 1) / 2;

		if (pq->buffer[parent].priority < priority) {
			pq->buffer[size] = pq->buffer[parent];
			size = parent;
		}
		else {
			break;
		}
	}

	pq->buffer[size] = (pq_entry_t) {
		.priority = priority,
		.udata = udata
	};
	pq->size++;

	return true;
}

void*
priority_queue_pop(priority_queue_t* pq)
{
	uint64_t size = pq->size;

	if (size == 0) {
		return NULL;
	}

	void* el = pq->buffer[0].udata;
	size--;

	uint64_t last_el_priority = pq->buffer[size].priority;

	uint64_t i = 0;
	// Continue bubbling up until we get to a node at index > the parent of
	// the element at index "size - 1", i.e. until > (size - 2) / 2, or
	// while < size / 2
	while (i < size / 2) {
		uint64_t lchild = 2 * i + 1;
		uint64_t rchild = 2 * i + 2;

		bool rchild_greater =
			pq->buffer[lchild].priority < pq->buffer[rchild].priority;

		uint64_t greater_child = lchild + (uint64_t) rchild_greater;
		if (last_el_priority < pq->buffer[greater_child].priority) {
			pq->buffer[i] = pq->buffer[greater_child];
			i = greater_child;
		}
		else {
			break;
		}
	}

	pq->buffer[i] = pq->buffer[size];
	pq->size = size;

	return el;
}

void*
priority_queue_peek(priority_queue_t* pq)
{
	if (pq->size == 0) {
		return NULL;
	}
	else {
		return pq->buffer[0].udata;
	}
}

