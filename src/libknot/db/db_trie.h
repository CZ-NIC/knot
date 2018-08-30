/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \addtogroup db
 * @{
 */

#pragma once

#include "libknot/db/db.h"

/* Native options. */
struct knot_db_trie_opts {
	unsigned unused;
};

/* Default options. */
#define KNOT_DB_TRIE_OPTS_INITIALIZER { \
	0 \
}

const knot_db_api_t *knot_db_trie_api(void);

/*! @} */
