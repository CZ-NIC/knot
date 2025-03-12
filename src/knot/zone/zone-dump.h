/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/skip.h"
#include "knot/zone/zone.h"

/*!
 * \brief Dumps given zone to text file.
 *
 * \param zone      Zone to be saved.
 * \param skip      RRRTypes to be skipped.
 * \param file      File to write to.
 * \param comments  Add separating comments indicator.
 * \param color     Optional color control sequence.
 *
 * \retval KNOT_EOK on success.
 * \retval < 0 if error.
 */
int zone_dump_text(zone_contents_t *zone, zone_skip_t *skip, FILE *file, bool comments, const char *color);
