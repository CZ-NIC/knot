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

#include "libknot/internal/macros.h"
#include "libknot/internal/errcode.h"

#define ERR_ITEM(name) { name, KNOT_##name }

typedef struct {
	int errno_code;
	int libknot_code;
} err_table_t;

/*!
 * \brief Errno to libknot error mapping table.
 */
static const err_table_t errno_to_errcode[] = {
	ERR_ITEM(ENOMEM),
	ERR_ITEM(EINVAL),
	ERR_ITEM(ENOTSUP),
	ERR_ITEM(EBUSY),
	ERR_ITEM(EAGAIN),
	ERR_ITEM(EACCES),
	ERR_ITEM(ECONNREFUSED),
	ERR_ITEM(EISCONN),
	ERR_ITEM(EADDRINUSE),
	ERR_ITEM(ENOENT),
	ERR_ITEM(EEXIST),
	ERR_ITEM(ERANGE),
	ERR_ITEM(EADDRNOTAVAIL),

	/* Terminator - default value. */
	{ 0, KNOT_ERROR }
};

int knot_map_errno(void)
{
	const err_table_t *err = errno_to_errcode;

	while (err->errno_code != 0 && err->errno_code != errno) {
		err++;
	}

	return err->libknot_code;
}
