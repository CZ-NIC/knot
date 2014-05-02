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

#pragma once

#include <stdint.h>

#include <dnssec/binary.h>

/*!
 * TSIG algorithms.
 */
typedef enum dnssec_tsig_algorithm {
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
const uint8_t *dnssec_tsig_algorithm_to_dname(dnssec_tsig_algorithm_t algorithm);

/*!
 * Get TSIG algorithm number from MAC name.
 *
 * \example dnssec_tsig_algorithm_from_name("hmac-sha256")
 */
dnssec_tsig_algorithm_t dnssec_tsig_algorithm_from_name(const char *name);
const char *dnssec_tsig_algorithm_to_name(dnssec_tsig_algorithm_t algorithm);


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
