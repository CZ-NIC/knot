/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stddef.h>
#include <sys/socket.h>

extern const size_t PROXYV2_HEADER_MAXLEN;

int proxyv2_header_offset(void *base, size_t len_base);

int proxyv2_addr_store(void *base, size_t len_base, struct sockaddr_storage *ss);

int proxyv2_write_header(char *buf, size_t buflen, int socktype, const struct sockaddr *src,
                         const struct sockaddr *dst);
