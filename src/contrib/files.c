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

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "contrib/string.h"
#include "libknot/errcode.h"

static int remove_file(const char *path, const struct stat *stat, int type, struct FTW *ftw)
{
	(void)stat;
	(void)ftw;
	if (type == FTW_DP) {
		return rmdir(path);
	} else {
		return unlink(path);
	}
}

bool remove_path(const char *path)
{
	return (0 == nftw(path, remove_file, 1, FTW_DEPTH | FTW_PHYS));
}

int make_dir(const char *path, mode_t mode, bool ignore_existing)
{
	if (mkdir(path, mode) == 0) {
		return KNOT_EOK;
	}

	if (!ignore_existing || errno != EEXIST) {
		return knot_map_errno();
	}

	assert(errno == EEXIST);

	struct stat st = { 0 };
	if (stat(path, &st) != 0) {
		return knot_map_errno();
	}

	if (!S_ISDIR(st.st_mode)) {
		return knot_map_errno_code(ENOTDIR);
	}

	return KNOT_EOK;
}

int make_path(const char *path, mode_t mode)
{
	if (path == NULL) {
		return KNOT_EINVAL;
	}

	char *dir = strdup(path);
	if (dir == NULL) {
		return KNOT_ENOMEM;
	}

	for (char *p = strchr(dir + 1, '/'); p != NULL; p = strchr(p + 1, '/')) {
		*p = '\0';
		if (mkdir(dir, mode) == -1 && errno != EEXIST) {
			free(dir);
			return knot_map_errno();
		}
		*p = '/';
	}

	free(dir);

	return KNOT_EOK;
}

int open_tmp_file(const char *path, char **tmp_name, FILE **file, mode_t mode)
{
	int ret;

	*tmp_name = sprintf_alloc("%s.XXXXXX", path);
	if (*tmp_name == NULL) {
		ret = KNOT_ENOMEM;
		goto open_tmp_failed;
	}

	int fd = mkstemp(*tmp_name);
	if (fd < 0) {
		ret = knot_map_errno();
		goto open_tmp_failed;
	}

	if (fchmod(fd, mode) != 0) {
		ret = knot_map_errno();
		close(fd);
		unlink(*tmp_name);
		goto open_tmp_failed;
	}

	*file = fdopen(fd, "w");
	if (*file == NULL) {
		ret = knot_map_errno();
		close(fd);
		unlink(*tmp_name);
		goto open_tmp_failed;
	}

	return KNOT_EOK;
open_tmp_failed:
	free(*tmp_name);
	*tmp_name = NULL;
	*file = NULL;

	assert(ret != KNOT_EOK);
	return ret;
}
