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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
/*!
 * \file
 *
 * \brief Common executives for utils.
 *
 * \addtogroup knot_utils
 * @{
 */

#pragma once

#include <time.h>

#include "utils/common/netio.h"
#include "utils/common/params.h"
#include "libknot/libknot.h"

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
 * \param style		Style of the otput.
 */
void print_footer_xfr(const size_t  total_len,
                      const size_t  msg_count,
                      const size_t  rr_count,
                      const net_t   *net,
                      const float   elapsed,
                      const time_t  exec_time,
                      const style_t *style);

/*!
 * \brief Prints one response packet.
 *
 * \param packet	Response packet.
 * \param net		Connection information.
 * \param size		Original packet wire size.
 * \param elapsed	Total elapsed time.
 * \param exec_time	Time of the packet creation.
 * \param incoming	Indicates if the packet is input.
 * \param style		Style of the otput.
 */
void print_packet(const knot_pkt_t *packet,
                  const net_t      *net,
                  const size_t     size,
                  const float      elapsed,
                  const time_t     exec_time,
                  const bool       incoming,
                  const style_t    *style);

/*! @} */
