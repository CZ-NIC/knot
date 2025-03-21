/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

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

/*
 * A convenient replacement of `struct sockaddr_storage` with smaller AF_UNIX storage.
 *
 * Ensure this structure isn't accessed at full `struct sockaddr_storage` range!
 *
 * The alignment is needed when this structure is an array type and a pointer to this
 * array is casted to `struct sockaddr_storage *` and accessed. UBSAN complains otherwise.
 *
 * The `sun_path` size is a result of:
 *   `sizeof(struct sockaddr_in6) - sizeof(sa_family_t) + 4B padding`.
 */
typedef union __attribute__ ((aligned (8))) {
	struct sockaddr ip;
	struct sockaddr_in ip4;
	struct sockaddr_in6 ip6;
	struct {
		sa_family_t sun_family;
		char sun_path[30];
	} un;
} sockaddr_t;

/*!
 * \brief Calculate current structure length based on its content.
 *
 * \param ss  Socket address (can be sockaddr_t).
 *
 * \return Number of bytes or error code.
 */
int sockaddr_len(const struct sockaddr_storage *ss);

/*!
 * \brief Compare addresses.
 *
 * \param a            First address (can be sockaddr_t).
 * \param b            Second address (can be sockaddr_t).
 * \param ignore_port  Ignore port indication.
 *
 * \return like memcmp(3)
 */
int sockaddr_cmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b,
                 bool ignore_port);

/*!
 * \brief Set address and port.
 *
 * \param ss       Socket address (CANNOT be sockaddr_t!).
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
 * \param[in]  ss        Socket address (can be sockaddr_t).
 * \param[out] addr_size Address length.
 *
 * \return Pointer to binary buffer of size addr_size.
 */
void *sockaddr_raw(const struct sockaddr_storage *ss, size_t *addr_size);

/*!
 * \brief Set raw address.
 *
 * \param ss             Socket address (CANNOT be sockaddr_t!).
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
 * \note String format: \<address>[@<port>], f.e. '127.0.0.1@53'
 *
 * \param buf     Destination for string representation.
 * \param maxlen  Maximum number of written bytes.
 * \param ss      Socket address (can be sockaddr_t).
 *
 * \return Number of bytes written on success, error code on failure.
 */
int sockaddr_tostr(char *buf, size_t maxlen, const struct sockaddr_storage *ss);

/*!
 * \brief Return port number from address.
 *
 * \param ss  Socket address (can be sockaddr_t).
 *
 * \return Port number or error code.
 */
int sockaddr_port(const struct sockaddr_storage *ss);

/*!
 * \brief Set port number.
 *
 * \param ss    Socket address (can be sockaddr_t).
 * \param port  Port to set.
 */
void sockaddr_port_set(struct sockaddr_storage *ss, uint16_t port);

/*!
 * \brief Get host FQDN address.
 *
 * \return Hostname string or NULL.
 */
char *sockaddr_hostname(void);

/*!
 * \brief Check if address is ANY address.
 *
 * \param ss  Socket address (can be sockaddr_t).
 */
bool sockaddr_is_any(const struct sockaddr_storage *ss);

/*!
 * \brief Check if two addresses match the given network prefix.
 *
 * \param ss1     First address (can be sockaddr_t).
 * \param ss2     Second address (can be sockaddr_t).
 * \param prefix  Prefix length.
 *
 * \return True on match.
 */
bool sockaddr_net_match(const struct sockaddr_storage *ss1,
                        const struct sockaddr_storage *ss2,
                        unsigned prefix);

/*!
 * \brief Check if the address is within the given address range (inclusive).
 *
 * \param ss      Address to check (can be sockaddr_t).
 * \param ss_min  Minimum address (can be sockaddr_t).
 * \param ss_max  Maximum address (can be sockaddr_t).
 *
 * \return True on match.
 */
bool sockaddr_range_match(const struct sockaddr_storage *ss,
                          const struct sockaddr_storage *ss_min,
                          const struct sockaddr_storage *ss_max);
