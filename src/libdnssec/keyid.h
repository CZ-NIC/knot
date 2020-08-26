/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
