/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
	return (remove_path(path, false) == KNOT_EOK);
}
