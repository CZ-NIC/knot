#pragma once

#include <stdint.h>

#include <dnssec/binary.h>

/*!
 * TSIG algorithms.
 */
typedef enum {
	DNSSEC_TSIG_UNKNOWN = 0,
	DNSSEC_TSIG_HMAC_MD5,
	DNSSEC_TSIG_HMAC_SHA1,
	DNSSEC_TSIG_HMAC_SHA224,
	DNSSEC_TSIG_HMAC_SHA256,
	DNSSEC_TSIG_HMAC_SHA384,
	DNSSEC_TSIG_HMAC_SHA512
} dnssec_tsig_algorithm_t;

/*!
 * Get TSIG algorithm number from domain name.
 *
 * \see https://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml
 */
dnssec_tsig_algorithm_t dnssec_tsig_algorithm_from_dname(const uint8_t *dname);

/*!
 * Get TSIG algorithm number from MAC name.
 *
 * \example dnssec_tsig_algorithm_from_name("hmac-sha256")
 */
dnssec_tsig_algorithm_t dnssec_tsig_algorithm_from_name(const char *name);

/*!
 * TSIG signing context.
 */
struct dnssec_tsig_ctx;
typedef struct dnssec_tsig_ctx dnssec_tsig_ctx_t;

/*!
 * Create new TSIG signing context.
 */
int dnssec_tsig_new(dnssec_tsig_ctx_t **ctx, dnssec_tsig_algorithm_t algorithm,
		    const dnssec_binary_t *key);

/*!
 * Cleanup TSIG signing context.
 */
void dnssec_tsig_free(dnssec_tsig_ctx_t *ctx);

/*!
 * Add data to be signed by TSIG.
 */
int dnssec_tsig_add(dnssec_tsig_ctx_t *ctx, const dnssec_binary_t *data);

/*!
 * Get size of the TSIG signature for given signing context.
 */
size_t dnssec_tsig_size(dnssec_tsig_ctx_t *ctx);

/*!
 * Get size of the TSIG signature for given algorithm.
 */
size_t dnssec_tsig_algorithm_size(dnssec_tsig_algorithm_t algorithm);

/*!
 * Write TSIG signature.
 */
int dnssec_tsig_write(dnssec_tsig_ctx_t *ctx, uint8_t *mac);
