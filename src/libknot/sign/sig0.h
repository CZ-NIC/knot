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

#ifndef _KNOT_SIGN_SIG1_H_
#define _KNOT_SIGN_SIG0_H_

#include "sign/key.h"

/*!
 * \brief DNSSEC Algorithm Numbers
 *
 * http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
 */
enum knot_dnssec_algorithm {
	// 0 reserved
	KNOT_DNSSEC_ALG_RSAMD5 = 1,
	KNOT_DNSSEC_ALG_DH = 2,
	KNOT_DNSSEC_ALG_DSA = 3,
	// 4 reserved
	KNOT_DNSSEC_ALG_RSASHA1 = 5,
	KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1 = 6,
	KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1 = 7,
	KNOT_DNSSEC_ALG_RSASHA256 = 8,
	// 9 reserved
	KNOT_DNSSEC_ALG_RSASHA512 = 10,
	// 11 reserved
	KNOT_DNSSEC_ALG_ECC_GOST = 12,
	KNOT_DNSSEC_ALG_ECDSAP256SHA256 = 13,
	KNOT_DNSSEC_ALG_ECDSAP384SHA384 = 14,
	// 15-122 unassigned
	// 123-151 reserved
	// 252 reserved for indirect keys
	// 253 private algorithm
	// 254 private algorithm OID
	// 255 reserved
};

typedef enum knot_dnssec_algorithm knot_dnssec_algorithm_t;

enum knot_dnssec_key_usage {
	KNOT_KEY_USAGE_NONE = 0,
	KNOT_KEY_USAGE_ZONE_SIGN = 1,
	KNOT_KEY_USAGE_TRANSACTION_SIGN = 2
};

typedef enum knot_dnssec_key_usage knot_dnssec_key_usage_t;

struct algorithm_callbacks;
typedef struct algorithm_callbacks algorithm_callbacks_t;

/*!
 * \brief DNSSEC key representation.
 */
struct knot_dnssec_key {
	knot_dname_t *name;			//!< Key name (idenfies signer).
	knot_dnssec_algorithm_t algorithm;	//!< Algorithm identification.
	const algorithm_callbacks_t *callbacks;	//!< Algorithm callbacks.
	void *algorithm_data;			//!< Algorithm state data.
};

typedef struct knot_dnssec_key knot_dnssec_key_t;

int knot_dnssec_key_from_params(const knot_key_params_t *params,
				knot_dnssec_key_t *key);

int knot_dnssec_key_free(knot_dnssec_key_t *key);

int knot_sig0_sign(uint8_t *wire, size_t *wire_size, size_t wire_max_size,
		   knot_dnssec_key_t *key);

#endif // _KNOT_SIGN_SIG0_H_
