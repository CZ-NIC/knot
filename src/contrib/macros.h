/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Common macros.
 */

#pragma once

#ifndef MIN
/*! \brief Type-safe minimum macro. */
#define MIN(a, b) \
	({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

/*! \brief Type-safe maximum macro. */
#define MAX(a, b) \
	({ __typeof__ (a) _x = (a); __typeof__ (b) _y = (b); _x > _y ? _x : _y; })
#endif

#ifndef likely
/*! \brief Optimize for x to be true value. */
#define likely(x) __builtin_expect((x), 1)
#endif

#ifndef unlikely
/*! \brief Optimize for x to be false value. */
#define unlikely(x) __builtin_expect((x), 0)
#endif

/*! \brief Helpers for aligning uint8_t pointers to 8-byte boundaries. */
#define PTR_ALIGN_MAX (sizeof(void *) - 1) // NOTE assuming sizeof(void *) is a power of two
#define PTR_ALIGN_SIZE(ptr) ((sizeof(void *) - ((uintptr_t)(ptr) & PTR_ALIGN_MAX)) & PTR_ALIGN_MAX)
#define PTR_ALIGN(ptr) ((ptr) + PTR_ALIGN_SIZE(ptr))
