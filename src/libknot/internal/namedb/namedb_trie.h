/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/internal/namedb/namedb.h"

/* Defines */
#define NAMEDB_TRIE_BUCKET_SIZE  253 /* 1 page per bucket, see hat-trie.h */

/* Native options. */
struct namedb_trie_opts {
	unsigned bucket_size; /*!< Trie bucket size. */
};

/* Default options. */
#define NAMEDB_TRIE_OPTS_INITIALIZER { \
	NAMEDB_TRIE_BUCKET_SIZE \
}

const namedb_api_t *namedb_trie_api(void);
