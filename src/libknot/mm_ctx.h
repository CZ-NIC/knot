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
