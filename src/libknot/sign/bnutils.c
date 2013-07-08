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

#include <config.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "sign/bnutils.h"
#include "common/base64.h"

/*!
 * \brief Convert Base64 encoded number into OpenSSL BIGNUM format.
 */
BIGNUM *knot_b64_to_bignum(const char *input)
{
	size_t size = strlen(input);
	uint8_t *decoded;
	int32_t decoded_size;
	BIGNUM *result;

	decoded_size = base64_decode_alloc((uint8_t *)input, size, &decoded);
	if (decoded_size < 0) {
		return NULL;
	}

	result = BN_bin2bn((unsigned char *)decoded, (int)decoded_size, NULL);
	free(decoded);

	return result;
}
