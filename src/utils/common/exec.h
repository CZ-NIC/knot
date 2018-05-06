/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <time.h>

#include "utils/common/netio.h"
#include "utils/common/params.h"
#include "libknot/libknot.h"
#include "contrib/json.h"

/*!
 * \brief Allocates empty packet and sets packet size and random id.
 *
 * \param max_size	Maximal packet size.
 *
 * \retval packet	if success.
 * \retval NULL		if error.
 */
knot_pkt_t *create_empty_packet(const uint16_t max_size);

/*!
 * \brief Prints information header for transfer.
 *
 * \param packet	Parsed packet.
 * \param style		Style of the output.
 */
void print_header_xfr(const knot_pkt_t *packet, const style_t *style);

/*!
 * \brief Prints answer section for 1 transfer message.
 *
 * \param packet	Response packet.
 * \param style		Style of the output.
 */
void print_data_xfr(const knot_pkt_t *packet, const style_t *style);

/*!
 * \brief Prints trailing statistics for transfer.
 *
 * \param total_len	Total reply size (all messages).
 * \param msg_count	Number of messages.
 * \param rr_count	Total number of answer records.
 * \param net		Connection information.
 * \param elapsed	Total elapsed time.
 * \param exec_time	Time of the packet creation.
 * \param style		Style of the output.
 */
void print_footer_xfr(const size_t  total_len,
                      const size_t  msg_count,
                      const size_t  rr_count,
                      const net_t   *net,
                      const float   elapsed,
                      const time_t  exec_time,
                      const style_t *style);

/*!
 * \brief Prints initial JSON part of XFR output.
 *
 * \param query		Query packet.
 * \param exec_time	Time of the packet creation.
 * \param style		Style of the output.
 *
 * \retval JSON witter	if success.
 * \retval NULL		if error.
 */
jsonw_t *print_header_xfr_json(const knot_pkt_t *query,
                               const time_t     exec_time,
                               const style_t    *style);

/*!
 * \brief Prints one XFR reply packet in JSON.
 *
 * \param w		JSON writter.
 * \param reply		Reply packet (possibly one of many).
 * \param exec_time	Time of the packet creation.
 */
void print_data_xfr_json(jsonw_t          *w,
                         const knot_pkt_t *reply,
                         const time_t     exec_time);

/*!
 * \brief Prints trailing JSON part of XFR output.
 *
 * \param w		JSON writter.
 * \param style		Style of the output.
 */
void print_footer_xfr_json(jsonw_t       **w,
                           const style_t *style);

/*!
 * \brief Prints one or query/reply pair of DNS packets in JSON format.
 *
 * \param query		Query DNS packet.
 * \param reply		Reply DNS packet.
 * \param net		Connection information.
 * \param exec_time	Time of the packet creation.
 * \param style		Style of the output.
 */
void print_packets_json(const knot_pkt_t *query,
                        const knot_pkt_t *reply,
                        const net_t      *net,
                        const time_t     exec_time,
                        const style_t    *style);

/*!
 * \brief Prints one DNS packet.
 *
 * \param packet	DNS packet.
 * \param net		Connection information.
 * \param size		Original packet wire size.
 * \param elapsed	Total elapsed time.
 * \param exec_time	Time of the packet creation.
 * \param incoming	Indicates if the packet is input.
 * \param style		Style of the output.
 */
void print_packet(const knot_pkt_t *packet,
                  const net_t      *net,
                  const size_t     size,
                  const float      elapsed,
                  const time_t     exec_time,
                  const bool       incoming,
                  const style_t    *style);
