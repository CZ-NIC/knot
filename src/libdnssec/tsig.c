/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "shared/dname.h"
#include "error.h"
#include "shared/shared.h"
#include "tsig.h"

struct dnssec_tsig_ctx {
	gnutls_mac_algorithm_t algorithm;
	gnutls_hmac_hd_t hash;
};

/*!
 * TSIG algorithm indentifiers.
 */
typedef struct {
	dnssec_tsig_algorithm_t id;
	gnutls_mac_algorithm_t gnutls_id;
	const char *name;
	const char *dname;
} algorithm_id_t;

/*!
 * DNAME to algorithm conversion table.
 */
static const algorithm_id_t ALGORITHM_ID_TABLE[] = {
	// RFC 4635
	{ DNSSEC_TSIG_HMAC_SHA1,   GNUTLS_MAC_SHA1,   "hmac-sha1",   "\x9hmac-sha1"   },
	{ DNSSEC_TSIG_HMAC_SHA224, GNUTLS_MAC_SHA224, "hmac-sha224", "\xbhmac-sha224" },
	{ DNSSEC_TSIG_HMAC_SHA256, GNUTLS_MAC_SHA256, "hmac-sha256", "\xbhmac-sha256" },
	{ DNSSEC_TSIG_HMAC_SHA384, GNUTLS_MAC_SHA384, "hmac-sha384", "\xbhmac-sha384" },
	{ DNSSEC_TSIG_HMAC_SHA512, GNUTLS_MAC_SHA512, "hmac-sha512", "\xbhmac-sha512" },
	// RFC 2845
	{ DNSSEC_TSIG_HMAC_MD5, GNUTLS_MAC_MD5, "hmac-md5", "\x8hmac-md5\x7sig-alg\x3reg\x3int" },
	{ 0 }
};

/*!
 * Algorithm match callback prototype.
 */
typedef bool (*algorithm_match_cb)(const algorithm_id_t *m, const void *data);

/*!
 * Lookup an algorithm in the algorithm table.
 */
static const algorithm_id_t *lookup_algorithm(algorithm_match_cb match,
					      const void *data)
{
	assert(match);

	for (const algorithm_id_t *a = ALGORITHM_ID_TABLE; a->id; a++) {
		if (match(a, data)) {
			return a;
		}
	}

	return NULL;
}

static bool match_dname(const algorithm_id_t *algorithm, const void *data)
{
	const uint8_t *search = data;
	return dname_equal(search, (uint8_t *)algorithm->dname);
}

static bool match_name(const algorithm_id_t *algorithm, const void *data)
{
	const char *search = data;
	return strcasecmp(search, algorithm->name) == 0;
}

static bool match_id(const algorithm_id_t *algorithm, const void *data)
{
	dnssec_tsig_algorithm_t search = (dnssec_tsig_algorithm_t)data;
	return algorithm->id == search;
}

/*!
 * Convert TSIG algorithm identifier to GnuTLS identifier.
 */
static gnutls_mac_algorithm_t algorithm_to_gnutls(dnssec_tsig_algorithm_t tsig)
{
	const algorithm_id_t *found = lookup_algorithm(match_id, (void *)tsig);
	return (found ? found->gnutls_id : GNUTLS_MAC_UNKNOWN);
}

/* -- public API ----------------------------------------------------------- */

_public_
dnssec_tsig_algorithm_t dnssec_tsig_algorithm_from_dname(const uint8_t *dname)
{
	if (!dname) {
		return DNSSEC_TSIG_UNKNOWN;
	}

	const algorithm_id_t *found = lookup_algorithm(match_dname, dname);
	return (found ? found->id : DNSSEC_TSIG_UNKNOWN);
}

_public_
const uint8_t *dnssec_tsig_algorithm_to_dname(dnssec_tsig_algorithm_t algorithm)
{
	const algorithm_id_t *found = lookup_algorithm(match_id, (void *)algorithm);
	return (found ? (uint8_t *)found->dname : NULL);
}

_public_
dnssec_tsig_algorithm_t dnssec_tsig_algorithm_from_name(const char *name)
{
	if (!name) {
		return DNSSEC_TSIG_UNKNOWN;
	}

	const algorithm_id_t *found = lookup_algorithm(match_name, name);
	return (found ? found->id : DNSSEC_TSIG_UNKNOWN);
}

_public_
const char *dnssec_tsig_algorithm_to_name(dnssec_tsig_algorithm_t algorithm)
{
	const algorithm_id_t *found = lookup_algorithm(match_id, (void *)algorithm);
	return (found ? found->name : NULL);
}

_public_
int dnssec_tsig_optimal_key_size(dnssec_tsig_algorithm_t tsig)
{
	gnutls_mac_algorithm_t mac = algorithm_to_gnutls(tsig);
	if (mac == GNUTLS_MAC_UNKNOWN) {
		return 0;
	}

	return gnutls_mac_get_key_size(mac) * CHAR_BIT;
}

_public_
int dnssec_tsig_new(dnssec_tsig_ctx_t **ctx_ptr,
                    dnssec_tsig_algorithm_t algorithm,
		    const dnssec_binary_t *key)
{
	if (!ctx_ptr || !key) {
		return DNSSEC_EINVAL;
	}

	dnssec_tsig_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	ctx->algorithm = algorithm_to_gnutls(algorithm);
	if (ctx->algorithm == GNUTLS_MAC_UNKNOWN) {
		free(ctx);
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	int result = gnutls_hmac_init(&ctx->hash, ctx->algorithm, key->data, key->size);
	if (result != 0) {
		free(ctx);
		return DNSSEC_SIGN_INIT_ERROR;
	}

	*ctx_ptr = ctx;

	return DNSSEC_EOK;
}

_public_
void dnssec_tsig_free(dnssec_tsig_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	gnutls_hmac_deinit(ctx->hash, NULL);
	free(ctx);
}

_public_
int dnssec_tsig_add(dnssec_tsig_ctx_t *ctx, const dnssec_binary_t *data)
{
	if (!ctx || !data) {
		return DNSSEC_EINVAL;
	}

	int result = gnutls_hmac(ctx->hash, data->data, data->size);
	if (result != 0) {
		return DNSSEC_SIGN_ERROR;
	}

	return DNSSEC_EOK;
}

_public_
size_t dnssec_tsig_size(dnssec_tsig_ctx_t *ctx)
{
	if (!ctx) {
		return 0;
	}

	return gnutls_hmac_get_len(ctx->algorithm);
}

_public_
size_t dnssec_tsig_algorithm_size(dnssec_tsig_algorithm_t algorithm)
{
	int gnutls_algorithm = algorithm_to_gnutls(algorithm);
	return gnutls_hmac_get_len(gnutls_algorithm);
}

_public_
int dnssec_tsig_write(dnssec_tsig_ctx_t *ctx, uint8_t *mac)
{
	if (!ctx || !mac) {
		return DNSSEC_EINVAL;
	}

	gnutls_hmac_output(ctx->hash, mac);

	return DNSSEC_EOK;
}
