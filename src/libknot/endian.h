/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
