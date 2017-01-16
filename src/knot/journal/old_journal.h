/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdint.h>

#include "contrib/ucw/lists.h"

/*!
 * \brief Check if the journal file is used or not.
 *
 * \param path Journal file.
 *
 * \return true or false
 */
bool old_journal_exists(const char *path);

/*!
 * \brief Load changesets from journal.
 *
 * \param path Path to journal file.
 * \param zone Corresponding zone.
 * \param dst Store changesets here.
 * \param from Start serial.
 * \param to End serial.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERANGE if given entry was not found.
 * \return < KNOT_EOK on error.
 */
int old_journal_load_changesets(const char *path, const knot_dname_t *zone,
                                list_t *dst, uint32_t from, uint32_t to);
