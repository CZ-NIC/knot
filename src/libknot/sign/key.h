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

#ifndef _KNOT_SIGN_KEY_H_
#define _KNOT_SIGN_KEY_H_

#include <stdint.h>
#include "dname.h"
#include "tsig.h"

/*----------------------------------------------------------------------------*/

/*!
 * \brief Key attributes loaded from keyfile.
 */
struct knot_key_params {
	char *name;
	int algorithm;
	// parameters for symmetric cryptography
	char *secret;
	// parameters for public key cryptography
	char *modulus;
	char *public_exponent;
	char *private_exponent;
	char *prime_one;
	char *prime_two;
	char *exponent_one;
	char *exponent_two;
	char *coefficient;
};

typedef struct knot_key_params knot_key_params_t;

enum knot_key_type {
	KNOT_KEY_UNKNOWN = 0,
	KNOT_KEY_DNSSEC, //!< DNSSEC key. Described in RFC 2535 and RFC 4034.
	KNOT_KEY_TSIG,   //!< Transaction Signature. Described in RFC 2845.
	KNOT_KEY_TKEY    //!< Transaction Key. Described in RFC 2930.
};

typedef enum knot_key_type knot_key_type_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Calculates keytag from key wire.
 *
 * \param rdata		Key wireformat.
 * \param rdata_len	Wireformat size.
 *
 * \return uint16_t	Calculated keytag.
 */
uint16_t knot_keytag(const uint8_t *rdata, uint16_t rdata_len);

/*----------------------------------------------------------------------------*/

int knot_load_key_params(const char *filename, knot_key_params_t *key_params);
int knot_free_key_params(knot_key_params_t *key_params);
knot_key_type_t knot_get_key_type(const knot_key_params_t *key_params);

/*----------------------------------------------------------------------------*/

int knot_tsig_create_key(const char *name, int algorithm,
                         const char *b64secret, knot_tsig_key_t *key);

int knot_tsig_key_from_params(const knot_key_params_t *params,
                              knot_tsig_key_t *key);

int knot_tsig_key_free(knot_tsig_key_t *key);

#endif // _KNOT_SIGN_KEY_H_
