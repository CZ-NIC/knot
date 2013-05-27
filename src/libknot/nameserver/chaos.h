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
 * \file chaos.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \addtogroup query_processing
 * @{
 */

#ifndef _KNOT_CHAOS_H_
#define _KNOT_CHAOS_H_

#include <stdlib.h>
#include <stdint.h>

#include "name-server.h"
#include "packet/packet.h"

/*!
 * \brief Create a response for a given query in the CHAOS class.
 *
 * \param nameserver     Name server structure.
 * \param response       Response structure with parsed query.
 * \param response_wire  Output for response in wire format.
 * \param response_size  IN: maximum acceptable size of input, OUT: real size.
 *
 * \return Always KNOT_EOK.
 */
int knot_ns_answer_chaos(knot_nameserver_t *nameserver, knot_packet_t *response,
                         uint8_t *response_wire, size_t *response_size);

#endif // _KNOT_CHAOS_H_

/*! @} */
