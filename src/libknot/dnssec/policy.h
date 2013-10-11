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
 * \file policy.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Policy for handling of DNSSEC signatures and keys.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_POLICY_H_
#define _KNOT_DNSSEC_POLICY_H_

typedef enum knot_update_serial {
	KNOT_SOA_SERIAL_INC = 1 << 0,
	KNOT_SOA_SERIAL_KEEP = 1 << 1
} knot_update_serial_t;

typedef struct {
	uint32_t now;               //! Current time.
	uint32_t sign_lifetime;     //! Signature life time.
	uint32_t sign_refresh;      //! Sig. refresh time before expiration.
	bool forced_sign;           //! Drop valid signatures as well.
	knot_update_serial_t soa_up;//! Policy for serial updating.
} knot_dnssec_policy_t;

#define KNOT_DNSSEC_DEFAULT_LIFETIME 2592000

#define DEFAULT_DNSSEC_POLICY { .now = time_now(), \
				.sign_lifetime = KNOT_DNSSEC_DEFAULT_LIFETIME, \
				.sign_refresh = 7200, .forced_sign = false, \
				.soa_up = KNOT_SOA_SERIAL_INC }
#define FORCED_DNSSEC_POLICY {  .now = time_now(), \
				.sign_lifetime = KNOT_DNSSEC_DEFAULT_LIFETIME, \
				.sign_refresh = 7200, .forced_sign = true, \
				.soa_up = KNOT_SOA_SERIAL_INC }

#endif // _KNOT_DNSSEC_POLICY_H_

/*! @} */
