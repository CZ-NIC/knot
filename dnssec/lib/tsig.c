#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dname.h"
#include "error.h"
#include "shared.h"
#include "tsig.h"

struct dnssec_tsig_ctx {
	gnutls_mac_algorithm_t algorithm;
	gnutls_hmac_hd_t hash;
};

/*!
 * Convert TSIG algorithm identifier to GnuTLS identifier.
 */
static gnutls_mac_algorithm_t algorithm_to_gnutls(dnssec_tsig_algorithm_t tsig)
{
	switch(tsig) {
	case DNSSEC_TSIG_HMAC_MD5:    return GNUTLS_MAC_MD5;
	case DNSSEC_TSIG_HMAC_SHA1:   return GNUTLS_MAC_SHA1;
	case DNSSEC_TSIG_HMAC_SHA224: return GNUTLS_MAC_SHA224;
	case DNSSEC_TSIG_HMAC_SHA256: return GNUTLS_MAC_SHA256;
	case DNSSEC_TSIG_HMAC_SHA384: return GNUTLS_MAC_SHA384;
	case DNSSEC_TSIG_HMAC_SHA512: return GNUTLS_MAC_SHA512;
	default:
		return GNUTLS_MAC_UNKNOWN;
	}
}

typedef struct {
	const uint8_t *dname;
	dnssec_tsig_algorithm_t algorithm;
} algorithm_match_t;

/*!
 * DNAME to algorithm conversion table.
 */
static const algorithm_match_t ALGORITHM_TABLE[] = {
	// RFC 4635
	{ (uint8_t *)"\x9hmac-sha1",   DNSSEC_TSIG_HMAC_SHA1 },
	{ (uint8_t *)"\xbhmac-sha224", DNSSEC_TSIG_HMAC_SHA224 },
	{ (uint8_t *)"\xbhmac-sha256", DNSSEC_TSIG_HMAC_SHA256 },
	{ (uint8_t *)"\xbhmac-sha384", DNSSEC_TSIG_HMAC_SHA384 },
	{ (uint8_t *)"\xbhmac-sha512", DNSSEC_TSIG_HMAC_SHA512 },
	// RFC 2845
	{ (uint8_t *)"\x8hmac-md5\x7sig-alg\x3reg\x3int", DNSSEC_TSIG_HMAC_MD5 },
	{ NULL }
};

/* -- public API ----------------------------------------------------------- */

_public_
dnssec_tsig_algorithm_t dnssec_tsig_get_algorithm(const uint8_t *dname)
{
	for (const algorithm_match_t *m = ALGORITHM_TABLE; m->dname; m++) {
		if (dname_equal(dname, m->dname)) {
			return m->algorithm;
		}
	}

	return DNSSEC_TSIG_UNKNOWN;
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
