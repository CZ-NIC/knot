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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "libdnssec/binary.h"
#include "libdnssec/error.h"

#include "contrib/ctype.h"

/* -- binary to hex -------------------------------------------------------- */

static const char BIN_TO_HEX[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

int bin_to_hex_static(const dnssec_binary_t *bin, dnssec_binary_t *hex)
{
	if (!bin || !hex) {
		return DNSSEC_EINVAL;
	}

	if (bin->size * 2 != hex->size) {
		return DNSSEC_EINVAL;
	}

	for (size_t i = 0; i < bin->size; i++) {
		hex->data[2*i]   = BIN_TO_HEX[bin->data[i] >> 4];
		hex->data[2*i+1] = BIN_TO_HEX[bin->data[i] & 0x0f];
	}

	return DNSSEC_EOK;
}

int bin_to_hex(const dnssec_binary_t *bin, char **hex_ptr)
{
	if (!bin || !hex_ptr) {
		return DNSSEC_EINVAL;
	}

	size_t hex_size = bin->size * 2;
	char *hex = malloc(hex_size + 1);
	if (!hex) {
		return DNSSEC_ENOMEM;
	}

	dnssec_binary_t hex_bin = { .data = (uint8_t *)hex, .size = hex_size };
	bin_to_hex_static(bin, &hex_bin);
	hex[hex_size] = '\0';

	*hex_ptr = hex;

	return DNSSEC_EOK;
}

/* -- hex to binary -------------------------------------------------------- */

/*!
 * Convert HEX character to numeric value (assumes valid and lowercase input).
 */
static uint8_t hex_to_number(const char hex)
{
	if (hex >= '0' && hex <= '9') {
		return hex - '0';
	} else if (hex >= 'a' && hex <= 'f') {
		return hex - 'a' + 10;
	} else {
		assert(hex >= 'A' && hex <= 'F');
		return hex - 'A' + 10;
	}
}

/*!
 * Check if the input string has valid size and contains valid characters.
 */
static bool hex_valid_input(const dnssec_binary_t *hex)
{
	assert(hex);

	if (hex->size % 2 != 0) {
		return false;
	}

	for (int i = 0; i < hex->size; i++) {
		if (!is_xdigit(hex->data[i])) {
			return false;
		}
	}

	return true;
}

/*!
 * Perform hex to bin conversion without checking the validity.
 */
static void hex_to_bin_convert(const dnssec_binary_t *hex, dnssec_binary_t *bin)
{
	assert(hex);
	assert(bin);

	for (size_t i = 0; i < bin->size; i++) {
		uint8_t high = hex_to_number(hex->data[2 * i]);
		uint8_t low  = hex_to_number(hex->data[2 * i + 1]);
		bin->data[i] = high << 4 | low;
	}
}

int hex_to_bin_static(const dnssec_binary_t *hex, dnssec_binary_t *bin)
{
	if (!hex || !bin) {
		return DNSSEC_EINVAL;
	}

	if (hex->size / 2 != bin->size) {
		return DNSSEC_EINVAL;
	}

	if (!hex_valid_input(hex)) {
		return DNSSEC_MALFORMED_DATA;
	}

	hex_to_bin_convert(hex, bin);

	return DNSSEC_EOK;
}

int hex_to_bin(const char *hex_str, dnssec_binary_t *bin)
{
	if (!hex_str || !bin) {
		return DNSSEC_EINVAL;
	}

	dnssec_binary_t hex = { .data = (uint8_t *)hex_str, .size = strlen(hex_str) };
	if (!hex_valid_input(&hex)) {
		return DNSSEC_MALFORMED_DATA;
	}

	size_t bin_size = hex.size / 2;
	if (bin_size == 0) {
		bin->size = 0;
		bin->data = NULL;
		return DNSSEC_EOK;
	}

	int result = dnssec_binary_alloc(bin, bin_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	hex_to_bin_static(&hex, bin);

	return DNSSEC_EOK;
}
