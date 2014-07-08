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

    This program is distributed in the hope tha t it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>

#include "libknot/rrset.h"
#include "libknot/binary.h"
#include "libknot/util/utils.h"
#include "libknot/consts.h"

struct knot_tsig_key {
	knot_dname_t *name;
	knot_tsig_algorithm_t algorithm;
	knot_binary_t secret;
};

typedef struct knot_tsig_key knot_tsig_key_t;

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

/*! \brief Packet signing context.
 *  \todo This should be later moved to TSIG files when refactoring. */
typedef struct knot_sign_context {
	knot_tsig_key_t *tsig_key;
	uint8_t *tsig_buf;
	uint8_t *tsig_digest;
	size_t tsig_buflen;
	size_t tsig_digestlen;
	uint8_t tsig_runlen;
	uint64_t tsig_time_signed;
	size_t pkt_count;
} knot_sign_context_t;

/*!
 * \brief Create TSIG RDATA.
 *
 * \param rr TSIG RR to contain created data.
 * \param alg Algorithm name.
 * \param maclen Algorithm MAC len (may be set to 0 for empty MAC).
 * \param tsig_err TSIG error code.
 *
 * \retval KNOT_EINVAL
 * \retval KNOT_EOK
 */
int tsig_create_rdata(knot_rrset_t *rr, const knot_dname_t *alg,
                      uint16_t maclen, uint16_t tsig_err);

int tsig_rdata_set_time_signed(knot_rrset_t *tsig, uint64_t time);
int tsig_rdata_store_current_time(knot_rrset_t *tsig);
int tsig_rdata_set_fudge(knot_rrset_t *tsig, uint16_t fudge);
int tsig_rdata_set_mac(knot_rrset_t *tsig, uint16_t length,
                       const uint8_t *mac);
int tsig_rdata_set_orig_id(knot_rrset_t *tsig, uint16_t id);
//int tsig_rdata_set_tsig_error(knot_rrset_t *tsig, uint16_t tsig_error);
int tsig_rdata_set_other_data(knot_rrset_t *tsig, uint16_t length,
                              const uint8_t *other_data);

const knot_dname_t *tsig_rdata_alg_name(const knot_rrset_t *tsig);
knot_tsig_algorithm_t tsig_rdata_alg(const knot_rrset_t *tsig);
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
const char* tsig_alg_to_str(knot_tsig_algorithm_t alg);

/*!
 * \brief Convert TSIG algorithm identifier to domain name.
 *
 * \param alg TSIG algorithm identifier.
 *
 * \retval TSIG algorithm string name.
 * \retval Empty string if undefined.
 */
const knot_dname_t* tsig_alg_to_dname(knot_tsig_algorithm_t alg);

/*!
 * \brief Return TSIG RRSET maximum wire size for given algorithm.
 *
 * \param key Signing key descriptor.
 *
 * \return RRSET wire size.
 */
size_t tsig_wire_maxsize(const knot_tsig_key_t *key);

int tsig_rdata_is_ok(const knot_rrset_t *tsig);

/*! @} */
