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
 * \file rr-serialize.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Temporary RR serialization/deserialization functions.
 *
 * \note Valid until the new libknot API is finished.
 *
 * \addtogroup knot_utils
 * @{
 */

#ifndef _UTILS__RR_SERIALIZE_H_
#define _UTILS__RR_SERIALIZE_H_

#include "libknot/libknot.h"

/*!
 * \brief Serialize RRset to memory.
 * \param dst Pointer to memory block.
 * \param maxlen Remaining size of the memory block.
 * \param rrset Serialized RRset.
 *
 * Function may write something to dst even if it fails somewhere during that,
 * it is up to caller to clear it if neccessary.
 *
 * \retval number of written bytes on success
 * \retval KNOT_ERROR
 * \retval KNOT_ESPACE
 */
int rrset_write_mem(char *dst, size_t maxlen, const knot_rrset_t *rrset);

int rrset_header_write_mem(char *dst, size_t maxlen,
                           const knot_rrset_t *rrset,
                           const bool p_class, const bool p_ttl);

int rdata_write_mem(char* dst, size_t maxlen, const knot_rdata_t *rdata,
                    uint16_t type);

#endif // _UTILS__RR_SERIALIZE_H_

/*! @} */
