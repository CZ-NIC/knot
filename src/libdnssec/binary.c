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

#include <assert.h>
#include <stdarg.h>
#include <string.h>

#include "contrib/base64.h"
#include "libdnssec/binary.h"
#include "libdnssec/error.h"
#include "libdnssec/shared/shared.h"

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_binary_alloc(dnssec_binary_t *data, size_t size)
{
	if (!data || size == 0) {
		return DNSSEC_EINVAL;
	}

	uint8_t *new_data = calloc(1, size);
	if (!new_data) {
		return DNSSEC_ENOMEM;
	}

	data->data = new_data;
	data->size = size;

	return DNSSEC_EOK;
}

_public_
void dnssec_binary_free(dnssec_binary_t *binary)
{
	if (!binary) {
		return;
	}

	free(binary->data);
	clear_struct(binary);
}

_public_
int dnssec_binary_dup(const dnssec_binary_t *from, dnssec_binary_t *to)
{
	if (!from || !to) {
		return DNSSEC_EINVAL;
	}

	uint8_t *copy = malloc(from->size);
	if (copy == NULL) {
		return DNSSEC_ENOMEM;
	}

	memmove(copy, from->data, from->size);

	to->size = from->size;
	to->data = copy;

	return DNSSEC_EOK;
}

_public_
int dnssec_binary_resize(dnssec_binary_t *data, size_t new_size)
{
	if (!data) {
		return DNSSEC_EINVAL;
	}

	uint8_t *new_data = realloc(data->data, new_size);
	if (new_size > 0 && new_data == NULL) {
		return DNSSEC_ENOMEM;
	}

	data->data = new_data;
	data->size = new_size;

	return DNSSEC_EOK;
}

_public_
int dnssec_binary_cmp(const dnssec_binary_t *one, const dnssec_binary_t *two)
{
	if (one == two) {
		return 0;
	}

	uint8_t *data_one = one && one->size > 0 ? one->data : NULL;
	uint8_t *data_two = two && two->size > 0 ? two->data : NULL;

	if (data_one == data_two) {
		return 0;
	} else if (data_one == NULL) {
		return -1;
	} else if (data_two == NULL) {
		return +1;
	}

	size_t min_size = one->size <= two->size ? one->size : two->size;
	int cmp = memcmp(data_one, data_two, min_size);
	if (cmp != 0) {
		return cmp;
	} else if (one->size == two->size) {
		return 0;
	} else if (one->size < two->size) {
		return -1;
	} else {
		return +1;
	}
}

_public_
int dnssec_binary_from_base64(const dnssec_binary_t *base64,
			      dnssec_binary_t *binary)
{
	if (!base64 || !binary) {
		return DNSSEC_EINVAL;
	}

	uint8_t *data;
	int32_t size = knot_base64_decode_alloc(base64->data, base64->size, &data);
	if (size < 0) {
		return DNSSEC_EINVAL;
	}

	binary->data = data;
	binary->size = size;

	return DNSSEC_EOK;
}

_public_
int dnssec_binary_to_base64(const dnssec_binary_t *binary,
			    dnssec_binary_t *base64)
{
	if (!binary || !base64) {
		return DNSSEC_EINVAL;
	}

	uint8_t *data;
	int32_t size = knot_base64_encode_alloc(binary->data, binary->size, &data);
	if (size < 0) {
		return DNSSEC_EINVAL;
	}

	base64->data = data;
	base64->size = size;

	return DNSSEC_EOK;
}

_public_
int dnssec_binary_hash(dnssec_bin_hash_t alg, dnssec_binary_t *out, size_t nbin, ...)
{
	if (alg == DNSSEC_BIN_HASH_INVALID || !out || nbin == 0) {
		return DNSSEC_EINVAL;
	}

	gnutls_digest_algorithm_t gnutls_alg = GNUTLS_DIG_UNKNOWN;
	switch (alg) {
	case DNSSEC_BIN_HASH_INVALID: break;
	case DNSSEC_BIN_HASH_MD5:    gnutls_alg = GNUTLS_DIG_MD5;    break;
	case DNSSEC_BIN_HASH_SHA1:   gnutls_alg = GNUTLS_DIG_SHA1;   break;
	case DNSSEC_BIN_HASH_SHA256: gnutls_alg = GNUTLS_DIG_SHA256; break;
	case DNSSEC_BIN_HASH_SHA384: gnutls_alg = GNUTLS_DIG_SHA384; break;
	}

	_cleanup_hash_ gnutls_hash_hd_t digest = NULL;
	int r = gnutls_hash_init(&digest, gnutls_alg);
	if (r < 0) {
		return DNSSEC_HASH_ERROR;
	}

	va_list arg;
	va_start(arg, nbin);
	for (size_t i = 0; i < nbin; i++) {
		dnssec_binary_t *bin = va_arg(arg, dnssec_binary_t *);

		r = gnutls_hash(digest, bin->data, bin->size);
		if (r != 0) {
			return DNSSEC_HASH_ERROR;
		}
	}
	va_end(arg);

	out->size = gnutls_hash_get_len(gnutls_alg);
	out->data = malloc(out->size);
	if (out->data == NULL) {
		return DNSSEC_ENOMEM;
	}
	gnutls_hash_output(digest, out->data);
	return DNSSEC_EOK;
}
