/*!
 * \file hash-functions.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Various hash functions.
 *
 * All of the hash functions are downloaded from various sources.
 *
 * \todo Add references to sources.
 *
 * \addtogroup hashing
 * @{
 */
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

#ifndef _KNOT_HASH_FUNCTIONS_H_
#define _KNOT_HASH_FUNCTIONS_H_

#include <stdint.h>
#include <string.h>

/*
 * Fowler / Noll / Vo Hash (FNV Hash)
 * http://www.isthe.com/chongo/tech/comp/fnv/
 *
 * This is an implementation of the algorithms posted above.
 * This file is placed in the public domain by Peter Wemm.
 *
 * $FreeBSD: src/sys/sys/fnv_hash.h,v 1.2.2.1 2001/03/21 10:50:59 peter Exp $
 */

typedef uint32_t Fnv32_t;

#define FNV1_32_INIT ((Fnv32_t) 33554467UL)

#define FNV_32_PRIME ((Fnv32_t) 0x01000193UL)

static __inline Fnv32_t
fnv_32_buf(const void *buf, size_t len, Fnv32_t hval)
{
	const uint8_t *s = (const uint8_t *)buf;

	while (len-- != 0) {
		hval *= FNV_32_PRIME;
		hval ^= *s++;
	}
	return hval;
}

/*!
 * \brief Jenkins hash function.
 *
 * Downloaded from http://burtleburtle.net/bob/hash/evahash.html
 *
 * \param k Data to hash
 * \param length Size of the data in bytes.
 * \param initval The previous hash or an arbitrary value.
 *
 * \return Hash of the data.
 *
 * \todo Add source.
 */
typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

ub4 jhash(register ub1 *k, register ub4 length, register ub4 initval);

#endif /* _KNOT_HASH_FUNCTIONS_H_ */

/*! @} */
