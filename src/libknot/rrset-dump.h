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
 * \file rrset-dump.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief RRset text dump facility.
 *
 * \addtogroup libknot
 * @{
 */

#ifndef _KNOT_RRSETDUMP_H_
#define _KNOT_RRSETDUMP_H_

//#include <std>

#include "libknot/rrset.h"

int knot_rrset_txt_dump(const knot_rrset_t *rrset, char *dst, const size_t maxlen);

#endif // _KNOT_RRSETDUMP_H_

/*! @} */
