/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>

#include "libknot/internal/mempattern.h"
#include "libknot/internal/mempool.h"
/*! \todo Define the _public_ macro also in common/ */
#include "libknot/common.h"

static void mm_nofree(void *p)
{
	/* nop */
}

static void *mm_malloc(void *ctx, size_t n)
{
	(void)ctx;
	return malloc(n);
}

_public_
void *knot_mm_alloc(knot_mm_ctx_t *mm, size_t size)
{
	if (mm) {
		return mm->alloc(mm->ctx, size);
	} else {
		return malloc(size);
	}
}


_public_
void *knot_mm_realloc(knot_mm_ctx_t *mm, void *what, size_t size, size_t prev_size)
{
	if (mm) {
		void *p = mm->alloc(mm->ctx, size);
		if (p == NULL) {
			return NULL;
		} else {
			if (what) {
				memcpy(p, what,
				       prev_size < size ? prev_size : size);
			}
			knot_mm_free(mm, what);
			return p;
		}
	} else {
		return realloc(what, size);
	}
}

_public_
void knot_mm_free(knot_mm_ctx_t *mm, void *what)
{
	if (mm) {
		if (mm->free) {
			mm->free(what);
		}
	} else {
		free(what);
	}
}

_public_
void knot_mm_ctx_init(knot_mm_ctx_t *mm)
{
	mm->ctx = NULL;
	mm->alloc = mm_malloc;
	mm->free = free;
}

_public_
void knot_mm_ctx_mempool(knot_mm_ctx_t *mm, size_t chunk_size)
{
	mm->ctx = mp_new(chunk_size);
	mm->alloc = (knot_mm_alloc_t)mp_alloc;
	mm->free = mm_nofree;
}
