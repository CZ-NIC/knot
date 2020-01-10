/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdbool.h>
#include <stdint.h>

#include <sys/socket.h>

/*! \brief A packet with src & dst MAC & IP addrs + UDP payload. */
typedef struct {
	struct sockaddr_storage ip_from;
	struct sockaddr_storage ip_to;
	uint8_t eth_from[6];
	uint8_t eth_to[6];
	struct iovec payload;
} knot_xsk_msg_t;

/*! \brief Context structure for une XDP socket. */
struct knot_xsk_socket;

/*!
 * \brief Initialize XDP socket.
 *
 * \param socket        Socket ctx.
 * \param ifname        Name of the net iface (e.g. eth0).
 * \param if_queue      Network card queue to be used (normally 1 socket per each queue).
 * \param listen_port   Port to listen on.
 * \param load_bpf      Insert BPF program into packet processing.
 *
 * \return KNOT_E*
 */
int knot_xsk_init(struct knot_xsk_socket **socket, const char *ifname, int if_queue,
                  int listen_port, bool load_bpf);

/*! \brief De-init XDP socket. */
void knot_xsk_deinit(struct knot_xsk_socket *socket);

/*!
 * \brief Allocate one buffer for outgoing packet in shared umem.
 *
 * \param socket   XDP socket.
 * \param ipv6     The packet will use IPv6 (IPv4 otherwise).
 *
 * \return Pointer and size to UDP payload, or { NULL, 0 }.
 */
struct iovec knot_xsk_alloc_frame(struct knot_xsk_socket *socket, bool ipv6);

/*!
 * \brief Send single packet thru XDP.
 *
 * \param socket   XDP socket.
 * \param msg      Packet to be sent.
 *
 * \note The packet payload must have been allocated by knot_xsk_alloc_frame()!
 * \note Do not free the packet payload afterwards.
 *
 * \return KNOT_E*
 */
int knot_xsk_sendmsg(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg);

/*!
 * \brief Send multiple packets thru XDP.
 *
 * \param socket   XDP socket.
 * \param msgs     Packets to be sent.
 * \param count    Number of packets.
 *
 * \note The packets payloads all must have been allocated by knot_xsk_alloc_frame()!
 * \note Do not free the packets payloads afterwards.
 * \note Packets with zero length will be skipped.
 *
 * \return KNOT_E*
 */
int knot_xsk_sendmmsg(struct knot_xsk_socket *socket, const knot_xsk_msg_t msgs[], uint32_t count);

/*!
 * \brief Receive multiple packets thru XDP.
 *
 * \param socket      XDP socket.
 * \param msgs        Output: structures to be fille din with incomming packets infos.
 * \param max_count   Limit for number of packets received at once.
 * \param count       Output: real number of received packets.
 *
 * \return KNOT_E*
 */
int knot_xsk_recvmmsg(struct knot_xsk_socket *socket, knot_xsk_msg_t msgs[], uint32_t max_count, uint32_t *count);

/*! \brief Free the payload of a received packet. */
void knot_xsk_free_recvd(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg);

/*! \brief Syscall to kernel to wake up the network card driver after knot_xsk_sendm/mmsg(). */
int knot_xsk_check(struct knot_xsk_socket *socket);

/*! \brief Returns a file descriptor to be polled on for incomming packets. */
int knot_xsk_get_poll_fd(struct knot_xsk_socket *socket);
