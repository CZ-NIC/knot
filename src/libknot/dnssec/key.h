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
/*!
 * \file key.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Interface for loading of DNSSEC keys.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdint.h>
#include <time.h>
#include "libknot/dname.h"
#include "libknot/binary.h"
#include "libknot/rrtype/tsig.h"

/*----------------------------------------------------------------------------*/

/*!
 * \brief Key attributes loaded from keyfile.
 */
typedef struct {
	// common parameters
	knot_dname_t *name;
	knot_binary_t rdata;
	int algorithm;
	uint16_t keytag;
	uint16_t flags;

	// shared key
	knot_binary_t secret;

	// RSA
	knot_binary_t modulus;
	knot_binary_t public_exponent;
	knot_binary_t private_exponent;
	knot_binary_t prime_one;
	knot_binary_t prime_two;
	knot_binary_t exponent_one;
	knot_binary_t exponent_two;
	knot_binary_t coefficient;

	// DSA
	knot_binary_t prime;
	knot_binary_t subprime;
	knot_binary_t base;
	knot_binary_t private_value;
	knot_binary_t public_value;

	// EC/GOST
	knot_binary_t private_key;

	// key lifetime
	//time_t time_created;
	time_t time_publish;
	time_t time_activate;
	//time_t time_revoke;
	time_t time_inactive;
	time_t time_delete;
    
    //dipapado: hack to indicate nsec5 from filename
    int nsec5;
} knot_key_params_t;

typedef enum {
	KNOT_KEY_UNKNOWN = 0,
	KNOT_KEY_DNSSEC, //!< DNSSEC key. Described in RFC 2535 and RFC 4034.
	KNOT_KEY_TSIG,   //!< Transaction Signature. Described in RFC 2845.
	KNOT_KEY_TKEY,    //!< Transaction Key. Described in RFC 2930.
    //dipapadop: NSEC5 key
    KNOT_KEY_NSEC5
} knot_key_type_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Calculates keytag from key wire.
 *
 * \param rdata      Key wireformat.
 * \param rdata_len  Wireformat size.
 *
 * \return Calculated keytag.
 */
uint16_t knot_keytag(const uint8_t *rdata, uint16_t rdata_len);

/*----------------------------------------------------------------------------*/

/*!
 * \brief Reads the key files and extracts key parameters.
 *
 * \param filename    The name of the file with stored key. It can be either
 *                    the name with '.key' or '.private' suffix or without
 *                    the suffix at all.
 * \param key_params  Output key parameters.
 *
 * \returns Error code, KNOT_EOK when succeeded.
 */
int knot_load_key_params(const char *filename, knot_key_params_t *key_params);

/*!
 * \brief Copies key params structure content.
 *
 * \param src  Source structure.
 * \param dst  Destination structure.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_copy_key_params(const knot_key_params_t *src, knot_key_params_t *dst);

/*!
 * \brief Frees the key parameters.
 *
 * \param key_params  Key parameters to be freed.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_free_key_params(knot_key_params_t *key_params);

/*!
 * \brief Get the type of the key.
 *
 * \param key_params	Key parameters.
 *
 * \return Key type.
 */
knot_key_type_t knot_get_key_type(const knot_key_params_t *key_params);

/*----------------------------------------------------------------------------*/

/*!
 * \brief Creates TSIG key.
 *
 * \param name       Key name (aka owner name).
 * \param algorithm  Algorithm number.
 * \param b64secret  Shared secret encoded in Base64.
 * \param key        Output TSIG key.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_tsig_create_key(const char *name, int algorithm,
                         const char *b64secret, knot_tsig_key_t *key);

/*!
 * \brief Creates TSIG key from key parameters.
 *
 * \param params  Structure with key parameters.
 * \param key     Output TSIG key.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_tsig_key_from_params(const knot_key_params_t *params,
                              knot_tsig_key_t *key);

/*!
 * \brief Frees TSIG key.
 *
 * The structure itself is not freed.
 *
 * \param key  TSIG key structure to be freed.
 *
 * \return Error code, KNOT_EOK when succeeded.
 */
int knot_tsig_key_free(knot_tsig_key_t *key);

/*! @} */
