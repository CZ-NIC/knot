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

#include "files.h"

#include "../../src/contrib/string.c"
#include "../../src/contrib/files.c"

#include <stdlib.h>

static char *make_temp(bool is_directory)
{
	char *tmpdir = getenv("TMPDIR");
	if (!tmpdir) {
		tmpdir = "/tmp";
	}

	char tmp[4096] = { 0 };
	int r = snprintf(tmp, sizeof(tmp), "%s/knot_unit.XXXXXX", tmpdir);
	if (r <= 0 || r >= sizeof(tmp)) {
		return NULL;
	}

	if (is_directory) {
		char *ret = mkdtemp(tmp);
		if (ret == NULL) {
			return NULL;
		}
	} else {
		int ret = mkstemp(tmp);
		if (ret == -1) {
			return NULL;
		}
		close(ret);
	}

	return strdup(tmp);
}

char *test_mktemp(void)
{
	return make_temp(false);
}

char *test_mkdtemp(void)
{
	return make_temp(true);
}

bool test_rm_rf(const char *path)
{
	return remove_path(path);
}
