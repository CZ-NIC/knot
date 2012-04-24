/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file crc.h
 *
 * \author UFO
 *
 * \brief Dummy interface to CRC function of libz library. Should be removed
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef __CRC_H__
#define __CRC_H__

#include <zlib.h>
#include <stdint.h>


/**
 * The type of the CRC values.
 *
 * This type must be big enough to contain at least 32 bits.
 *****************************************************************************/
typedef uint32_t crc_t;


/**
 * Calculate the initial crc value.
 *
 * \return     The initial crc value.
 *****************************************************************************/
static inline crc_t crc_init(void)
{
	return adler32(0L, NULL, 0);
}


/**
 * Update the crc value with new data.
 *
 * \param crc      The current crc value.
 * \param data     Pointer to a buffer of \a data_len bytes.
 * \param data_len Number of bytes in the \a data buffer.
 * \return         The updated crc value.
 *****************************************************************************/
static inline crc_t crc_update(crc_t crc, const unsigned char *data, size_t data_len)
{
	return adler32(crc, data, data_len);
}


/**
 * Calculate the final crc value.
 *
 * \param crc  The current crc value.
 * \return     The final crc value.
 *****************************************************************************/
static inline crc_t crc_finalize(crc_t crc)
{
    return crc;
}


#endif      /* __CRC_H__ */
