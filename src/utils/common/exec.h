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

#include "utils/common/netio.h"		// net_t
#include "utils/common/params.h"	// style_t
#include "libknot/libknot.h"

extern knot_lookup_table_t opcodes[];
extern knot_lookup_table_t rcodes[];
extern knot_lookup_table_t rtypes[];

knot_packet_t* create_empty_packet(const knot_packet_prealloc_type_t type,
                                   const size_t                      max_size);

void print_header_xfr(const char     *owner,
                      const uint16_t type,
                      const style_t  *style);

void print_data_xfr(const knot_packet_t *packet,
                    const style_t       *style);

void print_footer_xfr(const size_t   total_len,
                      const size_t   msg_count,
                      const size_t   rr_count,
                      const net_t    *net,
                      const float    elapsed,
                      const style_t  *style);

void print_packet(const knot_packet_t *packet,
                  const size_t        total_len,
                  const net_t         *net,
                  const float         elapsed,
                  const bool          incoming,
                  const style_t       *style);

#endif // _UTILS__EXEC_H_

/*! @} */
