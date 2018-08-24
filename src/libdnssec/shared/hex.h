/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "libdnssec/binary.h"

/*!
 * Convert binary data to preallocated hexadecimal string.
 */
int bin_to_hex_static(const dnssec_binary_t *bin, dnssec_binary_t *hex);

/**
 * Convert binary data to hexadecimal string.
 */
int bin_to_hex(const dnssec_binary_t *bin, char **hex_ptr);

/*!
 * Convert hex encoded string to preallocated binary data.
 */
int hex_to_bin_static(const dnssec_binary_t *hex, dnssec_binary_t *bin);

/*!
 * Convert hex encoded string to binary data.
 */
int hex_to_bin(const char *hex, dnssec_binary_t *bin);
