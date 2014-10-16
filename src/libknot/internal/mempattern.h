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
/*!
 * \file mempattern.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Memory allocation related functions.
 *
 * \addtogroup alloc
 * @{
 */

#pragma once

#include <stddef.h>

/* Default memory block size. */
#define MM_DEFAULT_BLKSIZE 4096

/* Memory allocation function prototypes. */
typedef void* (*knot_mm_alloc_t)(void* ctx, size_t len);
typedef void (*knot_mm_free_t)(void *p);
typedef void (*knot_mm_flush_t)(void *p);

/*! \brief Memory allocation context. */
typedef struct mm_ctx {
	void *ctx; /* \note Must be first */
	knot_mm_alloc_t alloc;
	knot_mm_free_t free;
} knot_mm_ctx_t;

/*! \brief Allocs using 'mm' if any, uses system malloc() otherwise. */
void *knot_mm_alloc(knot_mm_ctx_t *mm, size_t size);
/*! \brief Reallocs using 'mm' if any, uses system realloc() otherwise. */
void *knot_mm_realloc(knot_mm_ctx_t *mm, void *what, size_t size, size_t prev_size);
/*! \brief Free using 'mm' if any, uses system free() otherwise. */
void knot_mm_free(knot_mm_ctx_t *mm, void *what);

/*! \brief Initialize default memory allocation context. */
void knot_mm_ctx_init(knot_mm_ctx_t *mm);

/*! \brief Memory pool context. */
void knot_mm_ctx_mempool(knot_mm_ctx_t *mm, size_t chunk_size);

/*! @} */
