/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Heap memory trimmer.
 */

#pragma once

#ifdef HAVE_MALLOC_TRIM
#include <malloc.h>
#endif

/*!
 * \brief Trim excess heap memory.
 */
static inline void mem_trim(void)
{
#ifdef HAVE_MALLOC_TRIM
	malloc_trim(0);
#endif
	return;
}
