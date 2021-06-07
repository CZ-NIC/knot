/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "contrib/files.h"
#include "contrib/string.h"
#include "libknot/errcode.h"

#if defined(MAXBSIZE)
  #define BUFSIZE MAXBSIZE
#else
  #define BUFSIZE (64 * 1024)
#endif

char* abs_path(const char *path, const char *base_dir)
{
	if (path == NULL) {
		return NULL;
	} else if (path[0] == '/') {
		return strdup(path);
	} else {
		char *full_path;
		if (base_dir == NULL) {
			char *cwd = realpath("./", NULL);
			full_path = sprintf_alloc("%s/%s", cwd, path);
			free(cwd);
		} else {
			full_path = sprintf_alloc("%s/%s", base_dir, path);
		}
		return full_path;
	}
}

bool same_path(const char *path1, const char *path2)
{
	bool equal = false;
	int err = 0;

	struct stat sb1;
	if (stat(path1, &sb1) == 0) {
		struct stat sb2;
		if (stat(path2, &sb2) == 0) {
			if (sb1.st_dev == sb2.st_dev &&
			    sb1.st_ino == sb2.st_ino) {
				equal = true;
			}
		} else {
			err = errno;
		}
	} else {
		err = errno;
	}

	if (err != 0) {
		// Can't compare real absolute paths, as stat() failed already. Try the best.
		char *full_path1 = abs_path(path1, NULL);
		char *full_path2 = abs_path(path2, NULL);

		if (strcmp(full_path1, full_path2) == 0) {
			equal = true;
		}

		free(full_path1);
		free(full_path2);
	}

	return equal;
}

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
		return KNOT_EEXIST;
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

int copy_file(const char *dest, const char *src)
{
	if (dest == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	int ret = 0;
	char *buf = NULL, *tmp_name = NULL;
	FILE *file = NULL;

	FILE *from = fopen(src, "r");
	if (from == NULL) {
		ret = errno == ENOENT ? KNOT_EFILE : knot_map_errno();
		goto done;
	}

	buf = malloc(sizeof(*buf) * BUFSIZE);
	if (buf == NULL) {
		ret = KNOT_ENOMEM;
		goto done;
	}

	ret = open_tmp_file(dest, &tmp_name, &file, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (ret != KNOT_EOK) {
		goto done;
	}

	ssize_t cnt;
	while ((cnt = fread(buf, sizeof(*buf), BUFSIZE, from)) != 0 &&
	       (ret = (fwrite(buf, sizeof(*buf), cnt, file) == cnt))) {
	}

	ret = !ret || ferror(from);
	if (ret != 0) {
		ret = knot_map_errno();
		unlink(tmp_name);
		goto done;
	}

	ret = rename(tmp_name, dest);
	if (ret != 0) {
		ret = knot_map_errno();
		unlink(tmp_name);
		goto done;
	}
	ret = KNOT_EOK;

done:
	free(tmp_name);
	if (file != NULL) {
		fclose(file);
	}
	free(buf);
	if (from != NULL) {
		fclose(from);
	}
	return ret;
}
