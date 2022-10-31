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

#pragma once

#include <stddef.h>
#include <sys/socket.h>

extern const size_t PROXYV2_HEADER_MAXLEN;

int proxyv2_header_offset(void *base, size_t len_base);

int proxyv2_addr_store(void *base, size_t len_base, struct sockaddr_storage *ss);

int proxyv2_write_header(char *buf, size_t buflen, int socktype, const struct sockaddr *src,
                         const struct sockaddr *dst);
