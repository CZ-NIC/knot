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
#include "common/descriptor.h"

/*!
 * \brief Algorithm state data (internal).
 */
struct knot_dnssec_algorithm_context;
typedef struct knot_dnssec_algorithm_context knot_dnssec_algorithm_context_t;

/*!
 * \brief DNSSEC key representation.
 */
struct knot_dnssec_key {
	knot_dname_t *name;			//!< Key name (idenfies signer).
	uint16_t keytag;			//!< Key tag (for fast lookup).
	knot_dnssec_algorithm_t algorithm;	//!< Algorithm identification.
	knot_dnssec_algorithm_context_t *context; //!< Implementation context.
};
typedef struct knot_dnssec_key knot_dnssec_key_t;

/*!
 * \brief Fill DNSSEC key structure according to key parameters.
 *
 * \param params	Key parameters.
 * \param key		Output structure.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_key_from_params(const knot_key_params_t *params,
				knot_dnssec_key_t *key);

/*!
 * \brief Free DNSSEC key structure content.
 *
 * \note Does not free the structure itself.
 *
 * \param key		DNSSEC key.
 *
 * \return Error code, always KNOT_EOK.
 */
int knot_dnssec_key_free(knot_dnssec_key_t *key);

/*!
 * \brief Sign a packet using SIG(0) mechanism.
 *
 * \param wire		Wire (packet content).
 * \param wire_size	Size of the wire.
 * \param wire_max_size	Capacity of the wire.
 * \param key		DNSSEC key to be used for signature.
 *
 * \return Error code, KNOT_EOK if succeeded.
 */
int knot_sig0_sign(uint8_t *wire, size_t *wire_size, size_t wire_max_size,
		   knot_dnssec_key_t *key);

#endif // _KNOT_SIGN_SIG0_H_
