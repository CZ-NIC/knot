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

/*!
 * \brief Return the required length for payload buffer.
 */
inline static size_t tcp_payload_len(const struct iovec *payload)
{
	assert(payload->iov_len >= 2);
	uint16_t val;
	memcpy(&val, payload->iov_base, sizeof(val));
	return be16toh(val) + sizeof(val);
}

/*!
 * \brief Handle DNS-over-TCP payloads in buffer and message.
 *
 * \param buffer         In/out: persistent buffer to store incomplete DNS payloads between receiving packets.
 * \param data           In/out: momental DNS payloads in incoming packet.
 * \param data_tofree    Out: once more DNS payload defragmented from multiple packets.
 * \param buffers_total  In/Out: total size of buffers (will be increased or decreased).
 *
 * \return KNOT_EOK, KNOT_ENOMEM
 */
int tcp_inbuf_update(struct iovec *buffer, struct iovec *data,
                     struct iovec *data_tofree, size_t *buffers_total);

/*! @} */
