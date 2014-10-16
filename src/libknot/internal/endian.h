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

#pragma once

#if defined(__linux__)
#	include <endian.h>
# ifndef HAVE_BE64TOH
#       include <arpa/inet.h>
#       define be32toh(x) ntohl(x)
#       define be16toh(x) ntohs(x)
#  if BYTE_ORDER == LITTLE_ENDIAN
#       include <byteswap.h>
#       define be64toh(x) bswap_64 (x)
#  else
#       define be64toh(x) (x)
#  endif
# endif
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#	include <sys/endian.h>
#elif defined(__OpenBSD__)
#	include <sys/types.h>
#	define be16toh(x) betoh16(x)
#	define be32toh(x) betoh32(x)
#	define be64toh(x) betoh64(x)
#elif defined(__APPLE__)
#       include <libkern/OSByteOrder.h>
#       define be16toh(x) OSSwapBigToHostInt16(x)
#       define be32toh(x) OSSwapBigToHostInt32(x)
#       define be64toh(x) OSSwapBigToHostInt64(x)
#       define htobe16(x) OSSwapHostToBigInt16(x)
#       define htobe32(x) OSSwapHostToBigInt32(x)
#       define htobe64(x) OSSwapHostToBigInt64(x)
#endif
