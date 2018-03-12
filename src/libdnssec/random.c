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
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stddef.h>
#include <stdint.h>

#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libdnssec/shared/shared.h"

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_random_buffer(uint8_t *data, size_t size)
{
	if (!data) {
		return DNSSEC_EINVAL;
	}

	int result = gnutls_rnd(GNUTLS_RND_RANDOM, data, size);
	if (result != 0) {
		assert_unreachable();
		return DNSSEC_ERROR;
	}

	return DNSSEC_EOK;
}

_public_
int dnssec_random_binary(dnssec_binary_t *binary)
{
	if (!binary) {
		return DNSSEC_EINVAL;
	}

	return dnssec_random_buffer(binary->data, binary->size);
}
