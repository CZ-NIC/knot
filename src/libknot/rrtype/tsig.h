/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief TSIG manipulation.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdint.h>

#include "dnssec/binary.h"
#include "dnssec/tsig.h"
#include "libknot/binary.h"
#include "libknot/consts.h"
#include "libknot/rrset.h"
#include "libknot/tsig.h"

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
int knot_tsig_create_rdata(knot_rrset_t *rr, const knot_dname_t *alg,
                      uint16_t maclen, uint16_t tsig_err);

int knot_tsig_rdata_set_time_signed(knot_rrset_t *tsig, uint64_t time);

int knot_tsig_rdata_store_current_time(knot_rrset_t *tsig);

int knot_tsig_rdata_set_fudge(knot_rrset_t *tsig, uint16_t fudge);

int knot_tsig_rdata_set_mac(knot_rrset_t *tsig, uint16_t length, const uint8_t *mac);

int knot_tsig_rdata_set_orig_id(knot_rrset_t *tsig, uint16_t id);

int knot_tsig_rdata_set_other_data(knot_rrset_t *tsig, uint16_t length,
                              const uint8_t *other_data);

const knot_dname_t *knot_tsig_rdata_alg_name(const knot_rrset_t *tsig);

dnssec_tsig_algorithm_t knot_tsig_rdata_alg(const knot_rrset_t *tsig);

uint64_t knot_tsig_rdata_time_signed(const knot_rrset_t *tsig);

uint16_t knot_tsig_rdata_fudge(const knot_rrset_t *tsig);

const uint8_t *knot_tsig_rdata_mac(const knot_rrset_t *tsig);

size_t knot_tsig_rdata_mac_length(const knot_rrset_t *tsig);

uint16_t knot_tsig_rdata_orig_id(const knot_rrset_t *tsig);

uint16_t knot_tsig_rdata_error(const knot_rrset_t *tsig);

const uint8_t *knot_tsig_rdata_other_data(const knot_rrset_t *tsig);

uint16_t knot_tsig_rdata_other_data_length(const knot_rrset_t *tsig);

size_t knot_tsig_rdata_tsig_variables_length(const knot_rrset_t *tsig);

size_t knot_tsig_rdata_tsig_timers_length();

/*!
 * \brief Return TSIG RRSET maximum wire size for given algorithm.
 *
 * \param key Signing key descriptor.
 *
 * \return RRSET wire size.
 */
size_t knot_tsig_wire_maxsize(const knot_tsig_key_t *key);

/*! \todo Documentation. */
int knot_tsig_rdata_is_ok(const knot_rrset_t *tsig);

/*! @} */
