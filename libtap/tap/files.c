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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

static bool special_name(const char *name)
{
	return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

static bool rm_dir_contents(int dir_fd)
{
	DIR *dir = fdopendir(dir_fd);
	if (!dir) {
		return false;
	}

	bool success = true;

	struct dirent entry = { 0 };
	struct dirent *result = NULL;
	while (success && readdir_r(dir, &entry, &result) == 0 && result) {
		if (special_name(result->d_name)) {
			continue;
		}

		bool is_dir = result->d_type == DT_DIR;

		if (is_dir) {
			int sub = openat(dir_fd, result->d_name, O_NOFOLLOW);
			success = rm_dir_contents(sub);
			close(sub);
		}

		if (success) {
			int flags = is_dir ? AT_REMOVEDIR : 0;
			success = unlinkat(dir_fd, result->d_name, flags) == 0;
		}
	}

	closedir(dir);

	return success;
}

bool test_rm_rf(const char *path)
{
	if (!path) {
		return false;
	}

	int fd = open(path, O_NOFOLLOW);
	if (fd < 0) {
		return false;
	}

	struct stat st = { 0 };
	if (fstat(fd, &st) != 0) {
		close(fd);
		return false;
	}

	if (S_ISDIR(st.st_mode) && !rm_dir_contents(fd)) {
		close(fd);
		return false;
	}

	close(fd);
	return (remove(path) == 0);
}
