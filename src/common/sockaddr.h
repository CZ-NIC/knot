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
 * \file sockaddr.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Socket address abstraction layer.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_SOCKADDR_H_
#define _KNOTD_SOCKADDR_H_

/* BSD IPv6 */
#ifndef __POSIX_VISIBLE
#define __POSIX_VISIBLE = 200112
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

/*! \brief Universal socket address. */
typedef struct sockaddr_t {
	union {
		struct sockaddr_in addr4; /*!< IPv4 sockaddr. */
#ifndef DISABLE_IPV6
		struct sockaddr_in6 addr6; /*!< IPv6 sockaddr. */
#endif
	};
	socklen_t len;              /*!< Length of used sockaddr. */
	short prefix; /*!< Address prefix. */
} sockaddr_t;

/* Subnet maximum prefix length. */
#define IPV4_PREFIXLEN 32
#define IPV6_PREFIXLEN 128

/*! \brief Maximum address length in string format. */
#ifdef DISABLE_IPV6
#define SOCKADDR_STRLEN INET_ADDRSTRLEN
#else
#define SOCKADDR_STRLEN INET6_ADDRSTRLEN
#endif

/*!
 * \brief Initialize address structure.
 *
 * Members ptr and len will be initialized to correct address family.
 *
 * \param addr Socket address structure.
 * \param af Requested address family.
 *
 * \retval 0 on success.
 * \retval -1 on unsupported address family (probably INET6).
 */
int sockaddr_init(sockaddr_t *addr, int af);

/*!
 * \brief Return true value if sockaddr is valid.
 *
 * \param addr Socket address structure.
 *
 * \retval true on succes.
 * \retval false otherwise.
 */
int sockaddr_isvalid(sockaddr_t *addr);

/*!
 * \brief Copy socket address structure.
 *
 * \param dst Target address structure.
 * \param src Source address structure.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int sockaddr_copy(sockaddr_t *dst, const sockaddr_t *src);

/*!
 * \brief Set address and port.
 *
 * \param dst Target address structure.
 * \param family Address family.
 * \param addr IP address in string format.
 * \param port Port.
 *
 * \retval 0 if addr is not valid address in string format.
 * \retval positive value in case of success.
 * \retval -1 on error.
 * \see inet_pton(3)
 */
int sockaddr_set(sockaddr_t *dst, int family, const char* addr, int port);

/*!
 * \brief Set address prefix.
 *
 * \param dst Target address structure.
 * \param prefix Prefix.
 *
 * \retval 0 if success.
 * \retval -1 on error.
 */
int sockaddr_setprefix(sockaddr_t *dst, int prefix);

/*!
 * \brief Return string representation of socket address.
 *
 * \param addr Socket address structure.
 * \param dst Destination for string representation.
 * \param size Maximum number of written bytes.
 *
 * \retval 0 on success.
 * \retval -1 on invalid parameters.
 */
int sockaddr_tostr(const sockaddr_t *addr, char *dst, size_t size);

/*!
 * \brief Return port number from address.
 *
 * \param addr Socket address structure.
 *
 * \retval Port number on success.
 * \retval -1 on errors.
 */
int sockaddr_portnum(const sockaddr_t *addr);

/*!
 * \brief Return socket address family.
 * \param addr Socket address structure.
 * \return address family
 */
int sockaddr_family(const sockaddr_t *addr);

/*!
 * \brief Prepare to maximum largest size.
 * \return KNOT_EOK
 */
void sockaddr_prep(sockaddr_t *addr);

#endif /* _KNOTD_SOCKADDR_H_ */

/*! @} */
