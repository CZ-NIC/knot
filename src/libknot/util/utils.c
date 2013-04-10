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

#include <config.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#include "common.h"
#include "util/utils.h"
#include "common/prng.h"

/*----------------------------------------------------------------------------*/

knot_lookup_table_t *knot_lookup_by_name(knot_lookup_table_t *table,
                                             const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

knot_lookup_table_t *knot_lookup_by_id(knot_lookup_table_t *table,
                                           int id)
{
	while (table->name != NULL) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_random_id()
{
	return (uint16_t)(tls_rand() * ((uint16_t)~0));
}

struct flock* knot_file_lock(short type, short whence)
{
	static struct flock ret;
	ret.l_type = type;
	ret.l_start = 0;
	ret.l_whence = whence;
	ret.l_len = 0;
	ret.l_pid = getpid();
	return &ret;
}
