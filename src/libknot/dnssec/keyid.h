/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup keyid
 *
 * \brief DNSSEC key ID manipulation.
 *
 * The module contains auxiliary functions for manipulation with key IDs.
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/*!
 * Length of the key ID in presentation form (ASCII).
 */
#define DNSSEC_KEYID_SIZE 40

/*!
 * Length of the key ID in internal form (binary).
 */
#define DNSSEC_KEYID_BINARY_SIZE 20

/*!
 * Check if a provided string is a valid key ID string.
 */
bool dnssec_keyid_is_valid(const char *id);

/*!
 * Normalize the key ID string.
 */
void dnssec_keyid_normalize(char *id);

/*!
 * Create a normalized copy if the key ID.
 */
char *dnssec_keyid_copy(const char *id);

/*!
 * Check if two key IDs are equal.
 */
bool dnssec_keyid_equal(const char *one, const char *two);

/*! @} */
