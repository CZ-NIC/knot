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
/*  Copyright (C) 2011 CZ.NIC Labs

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

typedef  unsigned long int  u4;   /* unsigned 4-byte type */
typedef  unsigned     char  u1;   /* unsigned 1-byte type */

/*!
 * \brief Fowler/Noll/Vo Hash.
 *
 * Downloaded from ???
 *
 * \param data Data to hash.
 * \param size Size of the data in bytes.
 * \param bits
 *
 * \return Hash of the data.
 *
 * \todo Add source.
 */
unsigned long int fnv_hash(const char *data, int size, int bits);

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
u4 jhash(register u1 *k, u4 length, u4 initval);

#endif /* _KNOTDHASH_FUNCTIONS_H_ */

/*! @} */
