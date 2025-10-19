/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/*!
 * Maximal length of domain name including labels and length bytes.
 * \see RFC 1035
 */
#define DNAME_MAX_LENGTH 255

/*!
 * Maximal length of the domain name label, excluding the label size.
 * \see RFC 1035
 */
#define DNAME_MAX_LABEL_LENGTH 63

/*!
 * Get length of a domain name in wire format.
 */
size_t dname_length(const uint8_t *dname);

/*!
 * Copy domain name in wire format.
 */
uint8_t *dname_copy(const uint8_t *dname);

/*!
 * Normalize domain name in wire format.
 *
 * Currently converts all letters to lowercase.
 */
void dname_normalize(uint8_t *dname);

/*!
 * Check if two dnames are equal.
 *
 * Case insensitive.
 */
bool dname_equal(const uint8_t *one, const uint8_t *two);
