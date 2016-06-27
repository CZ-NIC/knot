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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

/* BSD IPv6 */
#ifndef __POSIX_VISIBLE
#define __POSIX_VISIBLE = 200112
#endif

#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>

/* Subnet maximum prefix length. */
#define IPV4_PREFIXLEN 32
#define IPV6_PREFIXLEN 128

/* Address string "address[@port]" maximum length. */
#define SOCKADDR_STRLEN_EXT (1 + 6) /* '@', 5 digits number, \0 */
#define SOCKADDR_STRLEN (sizeof(struct sockaddr_un) + SOCKADDR_STRLEN_EXT)

/*!
 * \brief Calculate current structure length based on address family.
 *
 * \param sa  Socket address.
 *
 * \return Number of bytes or error code.
 */
int sockaddr_len(const struct sockaddr *sa);

/*!
 * \brief Compare addresses.
 *
 * \return like memcmp(3)
 */
int sockaddr_cmp(const struct sockaddr *k1, const struct sockaddr *k2);

/*!
 * \brief Set address and port.
 *
 * \param ss       Socket address.
 * \param family   Address family.
 * \param straddr  IP address in string format.
 * \param port     Port.
 *
 * \return KNOT_EOK on success or an error code.
 */
int sockaddr_set(struct sockaddr_storage *ss, int family, const char *straddr, int port);

/*!
 * \brief Return raw network address in network byte order.
 *
 * \param[in]  sa        Socket address.
 * \param[out] addr_size Address length.
 *
 * \return Pointer to binary buffer of size addr_size.
 */
void *sockaddr_raw(const struct sockaddr *sa, size_t *addr_size);

/*!
 * \brief Set raw address.
 *
 * \param ss             Socket address.
 * \param family         Address family.
 * \param raw_addr       IP address in binary format.
 * \param raw_addr_size  Size of the binary address.
 *
 * \return KNOT_EOK on success or an error code.
 */
int sockaddr_set_raw(struct sockaddr_storage *ss, int family,
                     const uint8_t *raw_addr, size_t raw_addr_size);

/*!
 * \brief Return string representation of socket address.
 *
 * \note String format: <address>[@<port>], f.e. '127.0.0.1@53'
 *
 * \param buf     Destination for string representation.
 * \param maxlen  Maximum number of written bytes.
 * \param sa      Socket address.
 *
 * \return Number of bytes written on success, error code on failure.
 */
int sockaddr_tostr(char *buf, size_t maxlen, const struct sockaddr *sa);

/*!
 * \brief Return port number from address.
 *
 * \param sa  Socket address.
 *
 * \return Port number or error code.
 */
int sockaddr_port(const struct sockaddr *sa);

/*!
 * \brief Set port number.
 *
 * \param sa    Socket address.
 * \param port  Port to set.
 */
void sockaddr_port_set(struct sockaddr *sa, uint16_t port);

/*!
 * \brief Get host FQDN address.
 *
 * \return Hostname string or NULL.
 */
char *sockaddr_hostname(void);

/*!
 * \brief Check if address is ANY address.
 *
 * \param sa  Socket address.
 */
bool sockaddr_is_any(const struct sockaddr *sa);

/*!
 * \brief Check if two addresses match the given network prefix.
 *
 * \param sa1     First address.
 * \param sa2     Second address.
 * \param prefix  Prefix length.
 *
 * \return True on match.
 */
bool sockaddr_net_match(const struct sockaddr *sa1,
                        const struct sockaddr *sa2,
                        unsigned prefix);

/*!
 * \brief Check if the address is within the given address range (inclusive).
 *
 * \param sa      Address to check.
 * \param sa_min  Minimum address.
 * \param sa_max  Maximum address.
 *
 * \return True on match.
 */
bool sockaddr_range_match(const struct sockaddr *sa,
                          const struct sockaddr *sa_min,
                          const struct sockaddr *sa_max);
