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

#include "error.h"

#include <assert.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int fs_mkdir(const char *path, mode_t mode, bool ignore_existing)
{
	if (mkdir(path, mode) == 0) {
		return DNSSEC_EOK;
	}

	if (!ignore_existing || errno != EEXIST) {
		return dnssec_errno_to_error(errno);
	}

	assert(errno == EEXIST);

	struct stat st = { 0 };
	if (stat(path, &st) != 0) {
		return dnssec_errno_to_error(errno);
	}

	if (!S_ISDIR(st.st_mode)) {
		return dnssec_errno_to_error(ENOTDIR);
	}

	return DNSSEC_EOK;
}
