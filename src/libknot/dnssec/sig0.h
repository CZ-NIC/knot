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
 * \file sig0.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Interface for packet signing using SIG(0).
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_SIG0_H_
#define _KNOT_DNSSEC_SIG0_H_

#include "libknot/dnssec/sign.h"

/*!
 * \brief Sign a packet using SIG(0) mechanism.
 *
 * \param wire           Wire (packet content).
 * \param wire_size      Size of the wire.
 * \param wire_max_size  Capacity of the wire.
 * \param key            DNSSEC key to be used for signature.
 *
 * \return Error code, KNOT_EOK if succeeded.
 */
int knot_sig0_sign(uint8_t *wire, size_t *wire_size, size_t wire_max_size,
                   knot_dnssec_key_t *key);

#endif // _KNOT_DNSSEC_SIG0_H_

/*! @} */
