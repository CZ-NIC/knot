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
 * \file remote.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Functions for remote control interface.
 *
 * \addtogroup ctl
 * @{
 */

#pragma once

#include "libknot/libknot.h"
#include "knot/server/server.h"

/*! \brief Default connection control parameters. */
#define REMOTE_PORT	5533
#define REMOTE_SOCKET	"knot.sock"

/*!
 * \brief Bind RC interface.
 *
 * \param addr Interface descriptor (address, port).
 *
 * \retval socket if passed.
 * \retval knot_error else.
 */
int remote_bind(struct sockaddr_storage *addr);

/*!
 * \brief Unbind from RC interface and close socket.
 *
 * \note Breaks all pending connections.
 *
 * \param addr Interface descriptor (address, port).
 * \param socket Interface socket
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_unbind(struct sockaddr_storage *addr, int sock);

/*!
 * \brief Poll new events on RC socket.
 *
 * \param sock     RC interface socket.
 * \param sigmask  Signal mask to use during blocking waiting.
 *
 * \return number of polled events or -1 on error.
 */
int remote_poll(int sock, const sigset_t *sigmask);

/*!
 * \brief Start a RC connection with remote.
 *
 * \param r RC interface socket.
 * \param a Destination for remote party address (or NULL if not interested).
 * \param buf Buffer for RC command.
 * \param buflen Maximum buffer size.
 *
 * \return client TCP socket if success.
 * \return KNOT_ECONNREFUSED if fails to receive command.
 */
int remote_recv(int sock, struct sockaddr_storage *addr, uint8_t *buf,
                size_t *buflen);

/*!
 * \brief Parse a RC command.
 *
 * \param pkt Query packet.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_parse(knot_pkt_t *pkt);

/*!
 * \brief Execute command and prepare answer for client.
 *
 * \param fd Remote client
 * \param s Server instance.
 * \param pkt Parsed RC command.
 * \param rwire Buffer for response.
 * \param rlen Maximum buffer size for response.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_answer(int sock, server_t *s, knot_pkt_t *pkt);

/*!
 * \brief Accept new client, receive command, process it and send response.
 *
 * \note This should be used as a high-level API for workers.
 *
 * \param s Server instance.
 * \param ctl_addr Control interface address.
 * \param sock RC interface socket.
 * \param buf Buffer for commands/responses.
 * \param buflen Maximum buffer size.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_process(server_t *s, struct sockaddr_storage *ctl_addr, int sock,
                   uint8_t *buf, size_t buflen);

/* Functions for creating RC packets. */

/*!
 * \brief Build a RC command packet, TSIG key is optional.
 *
 * \note This doesn't sign packet, see remote_query_sign().
 *
 * \param query Command name, f.e. 'reload'.
 * \param key TSIG key for space reservation (or NULL).
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
knot_pkt_t* remote_query(const char *query, const knot_tsig_key_t *key);

/*!
 * \brief Sign a RC command packet using TSIG key.
 *
 * \param wire RC packet in wire format.
 * \param size RC packet size.
 * \param maxlen Maximum buffer size.
 * \param key TSIG key.
 *
 * \retval KNOT_EOK on success.
 * \retval knot_error else.
 */
int remote_query_sign(uint8_t *wire, size_t *size, size_t maxlen,
                      const knot_tsig_key_t *key);

/*!
 * \brief Initialize a rrset with the given name and type.
 *
 * \param rr Output rrset.
 * \param owner RRset owner.
 * \param type RRset type.
 *
 * \return KNOT_E*.
 */
int remote_build_rr(knot_rrset_t *rr, const char *owner, uint16_t type);

/*!
 * \brief Create a TXT rdata.
 *
 * \param rr Output rrset.
 * \param str Text string.
 * \param str_len Text string length.
 * \param index Rdata index (ensures correct argument position).
 *
 * \return KNOT_E*.
 */
int remote_create_txt(knot_rrset_t *rr, const char *str, size_t str_len,
                      uint16_t index);

/*!
 * \brief Create a NS rdata.
 *
 * \param rr Output rrset.
 * \param name Domain name as a string.
 *
 * \return KNOT_E*
 */
int remote_create_ns(knot_rrset_t *rr, const char *name);

/*!
 * \brief Print TXT rdata to stdout.
 *
 * \param rrset TXT rrset.
 * \param pos Rdata position in the rrset.
 *
 * \return KNOT_E*
 */
int remote_print_txt(const knot_rrset_t *rrset, uint16_t pos);

/*!
 * \brief Extracts TXT rdata into buffer.
 *
 * \param rrset TXT rrset.
 * \param pos Rdata position in the rrset.
 * \param out_len Output rdata blob length (optional).
 *
 * \return Rdata blob or NULL.
 */
uint8_t *remote_get_txt(const knot_rrset_t *rr, uint16_t pos, size_t *out_len);

/*! @} */
