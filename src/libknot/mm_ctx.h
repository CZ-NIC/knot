/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Memory allocation context.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stddef.h>

/* Memory allocation function prototypes. */
typedef void* (*knot_mm_alloc_t)(void *ctx, size_t len);
typedef void (*knot_mm_free_t)(void *p);

/*! \brief Memory allocation context. */
typedef struct knot_mm {
	void *ctx; /* \note Must be first */
	knot_mm_alloc_t alloc;
	knot_mm_free_t free;
} knot_mm_t;

/*! @} */
