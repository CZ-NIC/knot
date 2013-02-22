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
 * \file zone-dump.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Zone text dump facility.
 *
 * \addtogroup libknot
 * @{
 */

#ifndef _KNOT_ZONE_DUMP_H_
#define _KNOT_ZONE_DUMP_H_

#include "libknot/zone/zone.h"

/*!
 * \brief Dumps given zone to text (BIND-like) file.
 *
 * \param zone Zone to be saved.
 * \param File file to write to.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL if the specified file is not valid for writing.
 */
int zone_dump_text(knot_zone_contents_t *zone, FILE *f);

#endif // _KNOT_ZONE_DUMP_H_

/*! @} */
