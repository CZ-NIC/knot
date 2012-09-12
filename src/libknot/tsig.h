/*!
 * \file tsig.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief TSIG manipulation.
 *
 * \addtogroup libknot
 * @{
 */
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

#ifndef _KNOT_TSIG_H_
#define _KNOT_TSIG_H_

#include <stdint.h>

#include "rrset.h"
#include "util/utils.h"

/* The assigned numbers should not begin with 0 - reserved for error. */
enum tsig_algorithm {
	KNOT_TSIG_ALG_NULL = 0,
	KNOT_TSIG_ALG_GSS_TSIG = 128, /*!< \brief gss-tsig. */
	KNOT_TSIG_ALG_HMAC_MD5, /*!< \brief HMAC-MD5.SIG-ALG.REG.INT. */
	KNOT_TSIG_ALG_HMAC_SHA1, /*!< \brief hmac-sha1. */
	KNOT_TSIG_ALG_HMAC_SHA224, /*!< \brief hmac-sha224. */
	KNOT_TSIG_ALG_HMAC_SHA256, /*!< \brief hmac-sha256. */
	KNOT_TSIG_ALG_HMAC_SHA384, /*!< \brief hmac-sha384. */
	KNOT_TSIG_ALG_HMAC_SHA512 /*!< \brief hmac-sha512. */
};

typedef enum tsig_algorithm tsig_algorithm_t;

struct knot_key {
	knot_dname_t *name;   /*!< Key name. */
	tsig_algorithm_t algorithm; /*!< Key algorithm.  */
	char *secret;         /*!< Key data. */
	size_t secret_size;   /*!< Key length. */
};

typedef struct knot_key knot_key_t;

/*!< \todo FIND ALG LENGTHS */
enum tsig_algorithm_digest_length {
	KNOT_TSIG_ALG_DIG_LENGTH_GSS_TSIG = 0,
	KNOT_TSIG_ALG_DIG_LENGTH_HMAC_MD5 = 16,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA1 = 20,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA224 = 0,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA256 = 32,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA384 = 0,
	KNOT_TSIG_ALG_DIG_LENGTH_SHA512 = 0
};

enum tsig_consts {
	KNOT_TSIG_ITEM_COUNT = 7,
	KNOT_TSIG_VARIABLES_LENGTH = sizeof(uint16_t)	// class
	                             + sizeof(uint32_t)	// ttl
	                             + 6		// time signed
	                             + sizeof(uint16_t)	// fudge
	                             + sizeof(uint16_t)	// error
	                             + sizeof(uint16_t),// other data length
	KNOT_TSIG_TIMERS_LENGTH = sizeof(uint16_t)	//fugde
	                          + 6			// time signed
};

/*! TSIG errors are defined in common/errcode.h
 *  and present negative value of the TSIG error to
 *  comply with other parts of the library.
 *
 *  KNOT_TSIG_EBADSIG = -16
 *  KNOT_TSIG_EBADKEY = -17
 *  KNOT_TSIG_EBADTIME = -18
 */

/*!
 * \note Uses the given domain name, do not deallocate it!
 */
int tsig_rdata_set_alg_name(knot_rrset_t *tsig, knot_dname_t *alg_name);
int tsig_rdata_set_alg(knot_rrset_t *tsig, tsig_algorithm_t alg);
int tsig_rdata_set_time_signed(knot_rrset_t *tsig, uint64_t time);
int tsig_rdata_store_current_time(knot_rrset_t *tsig);
int tsig_rdata_set_fudge(knot_rrset_t *tsig, uint16_t fudge);
int tsig_rdata_set_mac(knot_rrset_t *tsig, uint16_t length,
                       const uint8_t *mac);
int tsig_rdata_set_orig_id(knot_rrset_t *tsig, uint16_t id);
int tsig_rdata_set_tsig_error(knot_rrset_t *tsig, uint16_t tsig_error);
int tsig_rdata_set_other_data(knot_rrset_t *tsig, uint16_t length,
                              const uint8_t *other_data);

const knot_dname_t *tsig_rdata_alg_name(const knot_rrset_t *tsig);
tsig_algorithm_t tsig_rdata_alg(const knot_rrset_t *tsig);
uint64_t tsig_rdata_time_signed(const knot_rrset_t *tsig);
uint16_t tsig_rdata_fudge(const knot_rrset_t *tsig);
const uint8_t *tsig_rdata_mac(const knot_rrset_t *tsig);
size_t tsig_rdata_mac_length(const knot_rrset_t *tsig);
uint16_t tsig_rdata_orig_id(const knot_rrset_t *tsig);
uint16_t tsig_rdata_error(const knot_rrset_t *tsig);
const uint8_t *tsig_rdata_other_data(const knot_rrset_t *tsig);
uint16_t tsig_rdata_other_data_length(const knot_rrset_t *tsig);
size_t tsig_rdata_tsig_variables_length(const knot_rrset_t *tsig);

size_t tsig_rdata_tsig_timers_length();

int tsig_alg_from_name(const knot_dname_t *name);

/*!
 * \brief Convert TSIG algorithm identifier to name.
 *
 * \param alg TSIG algorithm identifier.
 *
 * \retval TSIG algorithm string name.
 * \retval Empty string if undefined.
 */
const char* tsig_alg_to_str(tsig_algorithm_t alg);

uint16_t tsig_alg_digest_length(tsig_algorithm_t alg);

/*!
 * \brief Return TSIG RRSET maximum wire size for given algorithm.
 *
 * \param key Signing key descriptor.
 *
 * \return RRSET wire size.
 */
size_t tsig_wire_maxsize(const knot_key_t *key);
size_t tsig_wire_actsize(const knot_rrset_t *tsig);

int tsig_rdata_is_ok(const knot_rrset_t *tsig);

#endif /* _KNOT_TSIG_H_ */

/*! @} */
