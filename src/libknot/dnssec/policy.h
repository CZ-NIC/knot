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
/*!
 * \file policy.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Policy for handling of DNSSEC signatures and keys.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum knot_update_serial {
	KNOT_SOA_SERIAL_UPDATE = 1 << 0,
	KNOT_SOA_SERIAL_KEEP = 1 << 1
} knot_update_serial_t;

typedef struct {
	uint32_t now;               //! Current time.
	uint32_t refresh_before;    //! Refresh signatures expiring before to this time.
	uint32_t sign_lifetime;     //! Signature life time.
	bool forced_sign;           //! Drop valid signatures as well.
	knot_update_serial_t soa_up;//! Policy for serial updating.
} knot_dnssec_policy_t;

#define KNOT_DNSSEC_DEFAULT_LIFETIME 2592000

/*!
 * \brief Initialize default signing policy.
 */
void knot_dnssec_init_default_policy(knot_dnssec_policy_t *policy);

/*!
 * \brief Set policy timing data according to requested signature lifetime.
 */
void knot_dnssec_policy_set_sign_lifetime(knot_dnssec_policy_t *policy,
                                          uint32_t sign_lifetime);

/*!
 * \brief Get signature refresh time from the earliest expiration time.
 */
uint32_t knot_dnssec_policy_refresh_time(const knot_dnssec_policy_t *policy,
                                         uint32_t earliest_expiration);


/*! @} */
