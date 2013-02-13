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
 * \addtogroup knot_utils
 * @{
 */

#ifndef _UTILS__EXEC_H_
#define _UTILS__EXEC_H_

#include "libknot/packet/packet.h"	// knot_packet_t
#include "utils/common/netio.h"		// net_t
#include "utils/common/params.h"	// style_t

extern knot_lookup_table_t opcodes[];
extern knot_lookup_table_t rcodes[];
extern knot_lookup_table_t rtypes[];

knot_packet_t* create_empty_packet(knot_packet_prealloc_type_t t, int max_size);

void print_header_xfr(const style_t *style, const knot_rr_type_t type);

void print_data_xfr(const style_t       *style,
                    const knot_packet_t *packet);

void print_footer_xfr(const net_t    *net,
                      const style_t  *style,
                      const float    elapsed,
                      const size_t   total_len,
                      const size_t   msg_count);

void print_packet(const net_t         *net,
                  const style_t       *style,
                  const knot_packet_t *packet,
                  const float         elapsed,
                  const size_t        total_len,
                  const size_t        msg_count);

#endif // _UTILS__EXEC_H_

/*! @} */
