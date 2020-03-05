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

enum {
	KNOT_XDP_LISTEN_PORT_MASK = 0xFFFF0000, /*!< Listen port option mask. */
	KNOT_XDP_LISTEN_PORT_ALL  = 1 << 16,    /*!< Listen on all ports. */
	KNOT_XDP_LISTEN_PORT_DROP = 1 << 17,    /*!< Drop all incoming messages. */
};

/*! \brief A packet with src & dst MAC & IP addrs + UDP payload. */
typedef struct {
	struct sockaddr_storage ip_from;
	struct sockaddr_storage ip_to;
	uint8_t *eth_from;
	uint8_t *eth_to;
	struct iovec payload;
} knot_xsk_msg_t;

/*! \brief Styles of loading BPF program.
 *
 * \note In *all* the cases loading can only succeed if at the end
 *   a compatible BPF program is loaded on the interface.
 */
typedef enum {
	KNOT_XSK_LOAD_BPF_NEVER,  /*!< Do not load; error out if not loaded already. */
	KNOT_XSK_LOAD_BPF_ALWAYS, /*!< Always load a program (overwrite it). */
	KNOT_XSK_LOAD_BPF_MAYBE,  /*!< Try with present program or load if none. */
	/* Implementation caveat: when re-using program in _MAYBE case, we get a message:
	 * libbpf: Kernel error message: XDP program already attached */
} knot_xsk_load_bpf_t;

/*! \brief Context structure for one XDP socket. */
struct knot_xsk_socket;

/*!
 * \brief Initialize XDP socket.
 *
 * \param socket        Socket ctx; call with *socket == NULL.
 * \param ifname        Name of the net iface (e.g. eth0).
 * \param if_queue      Network card queue to be used (normally 1 socket per each queue).
 * \param listen_port   Port to listen on, or KNOT_XSK_LISTEN_PORT_ flag.
 * \param load_bpf      Insert BPF program into packet processing.
 *
 * \return KNOT_E*
 */
int knot_xsk_init(struct knot_xsk_socket **socket, const char *ifname, int if_queue,
                  uint32_t listen_port, knot_xsk_load_bpf_t load_bpf);

/*! \brief De-init XDP socket. */
void knot_xsk_deinit(struct knot_xsk_socket *socket);

/*!
 * \brief Collect completed TX buffers, so they can be used by knot_xsk_alloc_packet().
 *
 * \param socket   XDP socket.
 * \note Ideally you call it once just before each batch of _alloc_packet() calls.
 */
void knot_xsk_prepare_alloc(struct knot_xsk_socket *socket);

/*!
 * \brief Allocate one buffer for an outgoing packet.
 *
 * \param socket   XDP socket.
 * \param ipv6     The packet will use IPv6 (IPv4 otherwise).
 * \param out      Output: the allocated packet info.
 * \param in_reply_to   Optional: fill in addresses from a query.
 *
 * \return KNOT_E*
 */
int knot_xsk_alloc_packet(struct knot_xsk_socket *socket, bool ipv6,
                          knot_xsk_msg_t *out, const knot_xsk_msg_t *in_reply_to);

/*!
 * \brief Send multiple packets thru XDP.
 *
 * \param socket   XDP socket.
 * \param msgs     Packets to be sent.
 * \param count    Number of packets.
 * \param sent     Out: number of packet successfully sent.
 *
 * \note The packets all must have been allocated by knot_xsk_alloc_frame()!
 * \note Do not free the packets payloads afterwards.
 * \note Packets with zero length will be skipped.
 *
 * \return KNOT_E*
 */
int knot_xsk_sendmmsg(struct knot_xsk_socket *socket, const knot_xsk_msg_t msgs[],
                      uint32_t count, uint32_t *sent);

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
int knot_xsk_recvmmsg(struct knot_xsk_socket *socket, knot_xsk_msg_t msgs[],
                      uint32_t max_count, uint32_t *count);

/*! \brief Free payloads of received packets. */
void knot_xsk_free_recvd(struct knot_xsk_socket *socket, const knot_xsk_msg_t msgs[],
                         uint32_t count);

/*! \brief Syscall to kernel to wake up the network card driver after knot_xsk_sendm/mmsg(). */
int knot_xsk_sendmsg_finish(struct knot_xsk_socket *socket);

/*! \brief Returns a file descriptor to be polled on for incomming packets. */
int knot_xsk_get_poll_fd(struct knot_xsk_socket *socket);

/*! \brief Prints some info about the XDP socket. */
void knot_xsk_print_frames(const struct knot_xsk_socket *socket);
