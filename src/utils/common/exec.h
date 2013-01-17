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
 * \file exec.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief dig/host executives
 *
 * \addtogroup utils
 * @{
 */

#ifndef _UTILS__EXEC_H_
#define _UTILS__EXEC_H_

#include "libknot/packet/packet.h"	// packet_t
#include "utils/common/params.h"	// params_t
#include "utils/common/resolv.h"	// server_t

knot_packet_t* create_empty_packet(int max_size);
void process_query(const params_t *params, const query_t *query);

#endif // _UTILS__EXEC_H_

/*! @} */
