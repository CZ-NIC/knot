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

/*!
 * \file
 *
 * \brief Ethernet device info interface.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define KNOT_XDP_MAX_MTU 1790

/*!
 * \brief Get number of combined queues of a network interface.
 *
 * \param devname  Name of the ethdev (e.g. eth1).
 *
 * \retval < 0   KNOT_E* if error.
 * \retval 1     Default no of queues if the dev does not support.
 * \return > 0   Number of queues.
 */
int knot_eth_queues(const char *devname);

/*!
 * \brief Network card RSS configuration.
 */
typedef struct {
	size_t table_size; /*!< Size of indirection table in four-bytes. */
	size_t key_size;   /*!< Size of the RSS key in bytes. */
	uint32_t mask;     /*!< Input mask for accessing the table. */
	uint32_t data[];   /*!< Serialized key and table. */
} knot_eth_rss_conf_t;

/*!
 * \brief Get RSS configuration of a network interface.
 *
 * \param devname   Name of the ethdev (e.g. eth1).
 * \param rss_conf  Output RSS configuration. Must be freed explicitly.
 *
 * \return KNOT_E*
 */
int knot_eth_rss(const char *devname, knot_eth_rss_conf_t **rss_conf);

/*!
 * \brief Get value of MTU setup on a network interface.
 *
 * \param devname  Name of the ethdev (e.g. eth1).
 *
 * \retval < 0    KNOT_E* if error.
 * \return >= 0   Interface MTU.
 */
int knot_eth_mtu(const char *devname);

/*!
 * \brief Get the corresponding network interface name for the address.
 *
 * \param addr     Address of the interface.
 * \param out      Output buffer for the interface name.
 * \param out_len  Size of the output buffer.
 *
 * \return KNOT_E*
 */
int knot_eth_name_from_addr(const struct sockaddr_storage *addr, char *out,
                            size_t out_len);

/*!
 * \brief Get local IP address of given socket file descriptor.
 *
 * \param socket_fd    Interface socket.
 * \param mh           Optional: message header of a recvmsg'ed packet.
 * \param out          Output: detected local IP.
 *
 * \return KNOT_E*
 */
int knot_eth_addr_from_fd(int socket_fd, struct msghdr *mh,
                          struct sockaddr_storage *out);

/*!
 * \brief Get the mapping of interface index to VLAN tags.
 *
 * \param vlan_map       Output array of the mappings.
 * \param vlan_map_max   Maximum interface index allowed.
 *
 * \return KNOT_E*
 */
int knot_eth_vlans(uint16_t *vlan_map[], uint16_t *vlan_map_max);

typedef enum {
	KNOT_XDP_MODE_NONE, /*!< XDP not available, BPF not loaded, or error. */
	KNOT_XDP_MODE_FULL, /*!< Full XDP support in driver or HW. */
	KNOT_XDP_MODE_EMUL, /*!< Emulated XDP support. */
} knot_xdp_mode_t;

/*!
 * \brief Return the current XDP mode of a network interface.
 *
 * \param if_index  Index of the interface, output from if_nametoindex().
 *
 * \return Current XDP mode.
 */
knot_xdp_mode_t knot_eth_xdp_mode(int if_index);

/*! @} */
