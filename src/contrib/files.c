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

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

	struct dirent *result = NULL;
	while (success && (result = readdir(dir)) != NULL) {
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

bool remove_path(const char *path)
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
