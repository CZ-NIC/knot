/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup binary
 *
 * \brief Universal binary data container.
 *
 * The module provides universal binary data container extensively used by
 * a lot of functions provided by the library.
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>

/*!
 * Universal structure to hold binary data.
 */
typedef struct dnssec_binary {
	size_t size;	/*!< Size of the binary data. */
	uint8_t *data;	/*!< Stored data. */
} dnssec_binary_t;

/*!
 * Allocate new binary data structure.
 *
 * \param[out] data  Binary to be allocated.
 * \param[in]  size  Requested size of the binary.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_binary_alloc(dnssec_binary_t *data, size_t size);

/*!
 * Free content of binary structure.
 *
 * \param binary  Binary structure to be freed.
 */
void dnssec_binary_free(dnssec_binary_t *binary);

/*!
 * Create a copy of a binary structure.
 *
 * \param[in]  from  Source of the copy.
 * \param[out] to    Target of the copy.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_binary_dup(const dnssec_binary_t *from, dnssec_binary_t *to);

/*!
 * Resize binary structure to a new size.
 *
 * Internally uses realloc, which means that this function can be also used
 * as a malloc or free.
 *
 * \param data      Binary to be resized.
 * \param new_size  New size.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_binary_resize(dnssec_binary_t *data, size_t new_size);

/*!
 * Compare two binary structures (equivalent of memcmp).
 *
 * \note NULL sorts before data.
 *
 * \param one  First binary.
 * \param two  Second binary.
 *
 * \return 0 if one equals two, <0 if one sorts before two, >0 otherwise.
 */
int dnssec_binary_cmp(const dnssec_binary_t *one, const dnssec_binary_t *two);

/*!
 * Allocate binary from Base64 encoded string.
 *
 * \param[in]  base64  Base64 encoded data.
 * \param[out] binary  Decoded binary data.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_binary_from_base64(const dnssec_binary_t *base64,
			      dnssec_binary_t *binary);

/*!
 * Create Base64 encoded string from binary data.
 *
 * \param[in]  binary  Binary data.
 * \param[out] base64  Base64 encode data.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_binary_to_base64(const dnssec_binary_t *binary,
			    dnssec_binary_t *base64);
/*! @} */
