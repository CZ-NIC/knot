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
 * \file
 *
 * \brief Socket address abstraction layer.
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

/* BSD IPv6 */
#ifndef __POSIX_VISIBLE
#define __POSIX_VISIBLE = 200112
#endif

#include <sys/types.h>
#include <sys/socket.h>
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
 * \param ss Socket address storage.
 *
 * \return number of bytes or error code
 */
int sockaddr_len(const struct sockaddr *ss);

/*!
 * \brief Compare address storages.
 *
 * \return like memcmp(3)
 */
int sockaddr_cmp(const struct sockaddr_storage *k1, const struct sockaddr_storage *k2);

/*!
 * \brief Set address and port.
 *
 * \param ss Socket address storage.
 * \param family Address family.
 * \param straddr IP address in string format.
 * \param port Port.
 *
 * \return KNOT_EOK on success or an error code
 */
int sockaddr_set(struct sockaddr_storage *ss, int family, const char *straddr, int port);

/*!
 * \brief Return raw network address in network byte order.
 *
 * \param ss Socket address storage.
 * \param addr_size Length of the address will be stored in addr_size.
 * \return pointer to raw address
 */
void *sockaddr_raw(struct sockaddr_storage *ss, size_t *addr_size);

/*!
 * \brief Set raw address.
 *
 * \param ss Socket address storage.
 * \param family Address family.
 * \param raw_addr IP address in binary format.
 * \param raw_addr_size Size of the binary address.
 *
 * \return KNOT_EOK on success or an error code
 */
int sockaddr_set_raw(struct sockaddr_storage *ss, int family,
                     const uint8_t *raw_addr, size_t raw_addr_size);

/*!
 * \brief Return string representation of socket address.
 *
 * \note String format: <address>[@<port>], f.e. '127.0.0.1@53'
 *
 * \param ss Socket address storage.
 * \param buf Destination for string representation.
 * \param maxlen Maximum number of written bytes.
 *
 * \return Number of bytes written on success, error code on failure
 */
int sockaddr_tostr(char *buf, size_t maxlen, const struct sockaddr_storage *ss);

/*!
 * \brief Return port number from address.
 *
 * \param ss Socket address storage.
 *
 * \return port number or error code
 */
int sockaddr_port(const struct sockaddr_storage *ss);

/*!
 * \brief Set port number.
 *
 * \param ss Socket address storage.
 *
 */
void sockaddr_port_set(struct sockaddr_storage *ss, uint16_t port);

/*!
 * \brief Get host FQDN address.
 *
 * \return hostname string or NULL
 */
char *sockaddr_hostname(void);

/*! @} */
