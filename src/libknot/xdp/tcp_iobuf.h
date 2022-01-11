/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief TCP over XDP buffer helpers.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include <assert.h>
#include <string.h>
#include <sys/uio.h>

#include "libknot/endian.h"

struct tcp_outbuf {
	struct tcp_outbuf *next;
	uint32_t len;
	uint32_t seqno;
	bool sent;
	uint8_t bytes[];
};

struct tcp_outbufs; // see tcp.h

/*!
 * \brief Handle DNS-over-TCP payloads in buffer and message.
 *
 * \param buffer         In/out: persistent buffer to store incomplete DNS payloads between receiving packets.
 * \param data           In: momental DNS payloads in incoming packet.
 * \param inbufs         Out: list of incoming DNS messages.
 * \param inbufs_count   Out: number of inbufs.
 * \param buffers_total  In/Out: total size of buffers (will be increased or decreased).
 *
 * \return KNOT_EOK, KNOT_ENOMEM
 */
int tcp_inbuf_update(struct iovec *buffer, struct iovec data,
                     struct iovec **inbufs, size_t *inbufs_count,
                     size_t *buffers_total);

/*!
 * \brief Add payload to be sent by TCP, to output buffers.
 *
 * \param ob               Output buffers to be updated.
 * \param data             Payload to be sent.
 * \param len              Payload length.
 * \param mss              Connection outgoing MSS.
 * \param outbufs_total    In/out: total outbuf statistic to be updated.
 *
 * \return KNOT_E*
 */
int tcp_outbufs_add(struct tcp_outbufs *ob, uint8_t *data, size_t len,
                    uint32_t mss, size_t *outbufs_total);

/*!
 * \brief Remove+free acked data from output buffers.
 *
 * \param ob               Output buffers to be updated.
 * \param ackno            Ackno of received ACK.
 * \param outbufs_total    In/out: total outbuf statistic to be updated.
 */
void tcp_outbufs_ack(struct tcp_outbufs *ob, uint32_t ackno, size_t *outbufs_total);

/*!
 * \brief Prepare output buffers to be sent now.
 *
 * \param ob            Output buffers to be updated.
 * \param window_size   Connection outgoing window size.
 * \param resend        Send also possibly already sent data.
 * \param send_start    Out: first output buffer to be sent.
 * \param send_count    Out: number of output buffers to be sent.
 */
void tcp_outbufs_can_send(struct tcp_outbufs *ob, ssize_t window_size, bool resend,
                          struct tcp_outbuf **send_start, size_t *send_count);

/*!
 * \brief Compute allocated size of output buffers.
 */
size_t tcp_outbufs_usage(struct tcp_outbufs *ob);

/*! @} */
