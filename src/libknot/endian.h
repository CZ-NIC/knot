/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Endian dependent integer operations.
 *
 * \addtogroup wire
 * @{
 */

#pragma once

#if defined(__linux__) || defined(__gnu_hurd__) || \
    (defined(__FreeBSD_kernel__) && defined(__GLIBC__))
#       include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#       include <sys/endian.h>
#elif defined(__OpenBSD__) || defined(__sun) || defined(__CYGWIN__)
#       include <endian.h>
#elif defined(__APPLE__)
#       include <libkern/OSByteOrder.h>
#       define be16toh(x) OSSwapBigToHostInt16(x)
#       define be32toh(x) OSSwapBigToHostInt32(x)
#       define be64toh(x) OSSwapBigToHostInt64(x)
#       define htobe16(x) OSSwapHostToBigInt16(x)
#       define htobe32(x) OSSwapHostToBigInt32(x)
#       define htobe64(x) OSSwapHostToBigInt64(x)
#       define le16toh(x) OSSwapLittleToHostInt16(x)
#       define le32toh(x) OSSwapLittleToHostInt32(x)
#       define le64toh(x) OSSwapLittleToHostInt64(x)
#       define htole16(x) OSSwapHostToLittleInt16(x)
#       define htole32(x) OSSwapHostToLittleInt32(x)
#       define htole64(x) OSSwapHostToLittleInt64(x)
#endif

/*! @} */
