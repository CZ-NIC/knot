/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Memory allocation related functions.
 */

#pragma once

#include "libknot/mm_ctx.h"

/*! \brief Default memory block size. */
#define MM_DEFAULT_BLKSIZE 4096

/*! \brief Allocs using 'mm' if any, uses system malloc() otherwise. */
void *mm_alloc(knot_mm_t *mm, size_t size);

/*! \brief Callocs using 'mm' if any, uses system calloc() otherwise. */
void *mm_calloc(knot_mm_t *mm, size_t nmemb, size_t size);

/*! \brief Reallocs using 'mm' if any, uses system realloc() otherwise. */
void *mm_realloc(knot_mm_t *mm, void *what, size_t size, size_t prev_size);

/*! \brief Strdups using 'mm' if any, uses system strdup() otherwise. */
char *mm_strdup(knot_mm_t *mm, const char *s);

/*! \brief Free using 'mm' if any, uses system free() otherwise. */
void mm_free(knot_mm_t *mm, void *what);

/*! \brief Initialize default memory allocation context. */
void mm_ctx_init(knot_mm_t *mm);

/*! \brief Memory pool context. */
void mm_ctx_mempool(knot_mm_t *mm, size_t chunk_size);
