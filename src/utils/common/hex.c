/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "libknot/libknot.h"
#include "contrib/ctype.h"
#include "contrib/tolower.h"

/*!
 * \brief Convert HEX char to byte.
 * \note Expects valid lowercase letters.
 */
static uint8_t hex_to_num(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else {
		return c - 'a' + 10;
	}
}

/*!
 * \brief Convert string encoded in hex to bytes.
 */
int hex_decode(const char *input, uint8_t **output, size_t *output_size)
{
	if (!input || input[0] == '\0' || !output || !output_size) {
		return KNOT_EINVAL;
	}

	// input validation (length and content)

	size_t input_size = strlen(input);
	if (input_size % 2 != 0) {
		return KNOT_EMALF;
	}

	for (size_t i = 0; i < input_size; i++) {
		if (!is_xdigit(input[i])) {
			return KNOT_EMALF;
		}
	}

	// output allocation

	size_t result_size = input_size / 2;
	assert(result_size > 0);
	uint8_t *result = malloc(result_size);
	if (!result) {
		return KNOT_ENOMEM;
	}

	// conversion

	for (size_t i = 0; i < result_size; i++) {
		int high_nib = knot_tolower(input[2 * i]);
		int low_nib  = knot_tolower(input[2 * i + 1]);

		result[i] = hex_to_num(high_nib) << 4 | hex_to_num(low_nib);
	}

	*output = result;
	*output_size = result_size;

	return KNOT_EOK;
}
