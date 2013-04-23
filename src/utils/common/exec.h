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
 * \brief Common executives for utils.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _UTILS__EXEC_H_
#define _UTILS__EXEC_H_

#include "utils/common/netio.h"		// net_t
#include "utils/common/params.h"	// style_t
#include "libknot/libknot.h"

/*! \brief Holds data required between signing and signature verification. */
typedef struct {
	knot_tsig_key_t   tsig_key;
	knot_dnssec_key_t dnssec_key;
	uint8_t           *digest;
	size_t            digest_size;
} sign_context_t;

/*!
 * \brief Allocates empty packet and sets packet size and random id.
 *
 * \param type		Packet preallocation type.
 * \param max_size	Maximal packet size.
 *
 * \retval packet	if success.
 * \retval NULL		if error.
 */
knot_packet_t* create_empty_packet(const knot_packet_prealloc_type_t type,
                                   const size_t                      max_size);

/*!
 * \brief Prints information header for transfer.
 *
 * \param question	Packet question section.
 * \param style		Style of the output.
 */
void print_header_xfr(const knot_question_t *question, const style_t *style);

/*!
 * \brief Prints answer section for 1 transfer message.
 *
 * \param packet	Response packet.
 * \param style		Style of the output.
 */
void print_data_xfr(const knot_packet_t *packet,
                    const style_t       *style);

/*!
 * \brief Prints trailing statistics for transfer.
 *
 * \param total_len	Total reply size (all messages).
 * \param msg_count	Number of messages.
 * \param rr_count	Total number of answer records.
 * \param net		Connection information.
 * \param elapse	Total elapsed time.
 * \param style		Style of the otput.
 */
void print_footer_xfr(const size_t   total_len,
                      const size_t   msg_count,
                      const size_t   rr_count,
                      const net_t    *net,
                      const float    elapsed,
                      const style_t  *style);

/*!
 * \brief Prints one response packet.
 *
 * \param packet	Response packet.
 * \param total_len	Total reply size (all messages).
 * \param net		Connection information.
 * \param elapse	Total elapsed time.
 * \param incoming	Indicates if the packet is input.
 * \param style		Style of the otput.
 */
void print_packet(const knot_packet_t *packet,
                  const size_t        total_len,
                  const net_t         *net,
                  const float         elapsed,
                  const bool          incoming,
                  const style_t       *style);

/*!
 * \brief Cleans up sign context.
 *
 * \param ctx	Sign context.
 */
void free_sign_context(sign_context_t *ctx);

/*!
 * \brief Signs outgoing DNS packet.
 *
 * \param pkt		Packet to sign.
 * \param sign_ctx	Sign context.
 * \param key_params	Key parameters.
 *
 * \retval KNOT_EOK	if success.
 * \retval error code	if error.
 */
int sign_packet(knot_packet_t           *pkt,
                sign_context_t          *sign_ctx,
                const knot_key_params_t *key_params);

/*!
 * \brief Verifies signature for incoming DNS packet.
 *
 * \param pkt		Packet verify sign.
 * \param sign_ctx	Sign context.
 * \param key_params	Key parameters.
 *
 * \retval KNOT_EOK	if success.
 * \retval error code	if error.
 */
int verify_packet(const knot_packet_t     *pkt,
                  const sign_context_t    *sign_ctx,
                  const knot_key_params_t *key_params);

#endif // _UTILS__EXEC_H_

/*! @} */
