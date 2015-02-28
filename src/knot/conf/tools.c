/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "knot/conf/tools.h"
#include "knot/conf/conf.h"
#include "knot/conf/confdb.h"
#include "knot/conf/scheme.h"
#include "libknot/errcode.h"
#include "libknot/yparser/yptrafo.h"

static int hex_to_num(char hex) {
	if (hex >= '0' && hex <= '9') return hex - '0';
	if (hex >= 'a' && hex <= 'f') return hex - 'a' + 10;
	if (hex >= 'A' && hex <= 'F') return hex - 'A' + 10;
	return -1;
}

int hex_text_to_bin(
	char const *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len)
{
	// Check for hex notation (leading "0x").
	if (txt_len >= 2 && txt[0] == '0' && txt[1] == 'x') {
		txt += 2;
		txt_len -= 2;

		if (txt_len % 2 != 0) {
			return KNOT_EINVAL;
		} else if (*bin_len <= txt_len / 2) {
			return KNOT_ESPACE;
		}

		// Decode hex string.
		for (size_t i = 0; i < txt_len; i++) {
			if (isxdigit((int)txt[i]) == 0) {
				return KNOT_EINVAL;
			}

			bin[i] = 16 * hex_to_num(txt[2 * i]) +
			              hex_to_num(txt[2 * i + 1]);
		}

		*bin_len = txt_len / 2;
	} else {
		if (*bin_len <= txt_len) {
			return KNOT_ESPACE;
		}

		memcpy(bin, txt, txt_len);
		*bin_len = txt_len;
	}

	return KNOT_EOK;
}

int hex_text_to_txt(
	uint8_t const *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len)
{
	bool printable = true;

	// Check for printable string.
	for (size_t i = 0; i < bin_len; i++) {
		if (isprint(bin[i]) == 0) {
			printable = false;
			break;
		}
	}

	if (printable) {
		if (*txt_len <= bin_len) {
			return KNOT_ESPACE;
		}

		memcpy(txt, bin, bin_len);
		*txt_len = bin_len;
		txt[*txt_len] = '\0';
	} else {
		static const char *hex = "0123456789ABCDEF";

		if (*txt_len <= 2 + 2 * bin_len) {
			return KNOT_ESPACE;
		}

		// Write hex prefix.
		txt[0] = '0';
		txt[1] = 'x';
		txt += 2;

		// Encode data to hex.
		for (size_t i = 0; i < bin_len; i++) {
			txt[2 * i]     = hex[bin[i] / 16];
			txt[2 * i + 1] = hex[bin[i] % 16];
		}

		*txt_len = 2 + 2 * bin_len;
		txt[*txt_len] = '\0';
	}

	return KNOT_EOK;
}

int mod_id_to_bin(
	char const *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len)
{
	// Check for "mod_name/mod_id" format.
	char *pos = index(txt, '/');
	if (pos == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t name_len = pos - txt;
	char *id = pos + 1;
	size_t id_len = txt_len - name_len - 1;
	// Output is mod_name in yp_name_t format and zero terminated id string.
	size_t total_out_len = 1 + name_len + id_len + 1;

	// Check for enough output room.
	if (*bin_len < total_out_len) {
		return KNOT_ESPACE;
	}

	// Write mod_name in yp_name_t format.
	bin[0] = name_len;
	memcpy(bin + 1, txt, name_len);
	// Write mod_id as zero terminated string.
	memcpy(bin + 1 + name_len, id, id_len + 1);
	// Set output length.
	*bin_len = total_out_len;

	return KNOT_EOK;
}

int mod_id_to_txt(
	uint8_t const *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len)
{
	int ret = snprintf(txt, *txt_len, "%.*s/%s", (int)bin[0], bin + 1,
	                   bin + 1 + bin[0]);
	if (ret <= 0 || ret >= *txt_len) {
		return KNOT_ESPACE;
	}
	*txt_len = ret;

	return KNOT_EOK;
}

int check_ref(
	conf_args_t *args)
{
	const yp_item_t *parent = args->key1->var.r.ref;

	// Try to find the id in the referenced category.
	return conf_db_get(args->conf, args->txn, parent->name, NULL,
	                   args->data, args->data_len, NULL);
}

int check_modref(
	conf_args_t *args)
{
	const yp_name_t *mod_name = (const yp_name_t *)args->data;
	const uint8_t *id = args->data + 1 + args->data[0];
	size_t id_len = args->data_len - 1 - args->data[0];

	// Try to find the module with id.
	return conf_db_get(args->conf, args->txn, mod_name, NULL, id, id_len,
	                   NULL);
}

int include_file(
	conf_args_t *args)
{
	size_t max_path = 4096;
	char *path = malloc(max_path);
	if (path == NULL) {
		return KNOT_ENOMEM;
	}

	// Prepare absolute include path.
	int ret;
	if (args->data[0] == '/') {
		ret = snprintf(path, max_path, "%.*s",
		               (int)args->data_len, args->data);
	} else {
		char *full_current_name = realpath((args->file_name != NULL) ?
		                                   args->file_name : "./", NULL);
		if (full_current_name == NULL) {
			return KNOT_ENOMEM;
		}

		ret = snprintf(path, max_path, "%s/%.*s",
		               dirname(full_current_name),
		               (int)args->data_len, args->data);
		free(full_current_name);
	}
	if (ret <= 0 || ret >= max_path) {
		free(path);
		return ret;
	}
	size_t path_len = ret;

	// Get file status.
	struct stat file_stat;
	if (stat(path, &file_stat) != 0) {
		free(path);
		return KNOT_EINVAL;
	}

	// Process regular file.
	if (S_ISREG(file_stat.st_mode)) {
		ret = conf_parse(args->conf, args->txn, path, true,
		                 args->incl_depth);
		free(path);
		return ret;
	} else if (!S_ISDIR(file_stat.st_mode)) {
		free(path);
		return KNOT_EINVAL;
	}

	// Process directory.
	DIR *dir = opendir(path);
	if (dir == NULL) {
		free(path);
		return KNOT_EINVAL;
	}

	// Prepare own dirent structure (see NOTES in man readdir_r).
	size_t len = offsetof(struct dirent, d_name) +
	             fpathconf(dirfd(dir), _PC_NAME_MAX) + 1;
	struct dirent *entry = malloc(len);
	if (entry == NULL) {
		return KNOT_ENOMEM;
	}
	memset(entry, 0, len);

	struct dirent *result = NULL;
	while ((ret = readdir_r(dir, entry, &result)) == 0 && result != NULL) {
		// Skip names with leading dot.
		if (entry->d_name[0] == '.') {
			continue;
		}

		// Prepare included file absolute path.
		ret = snprintf(path + path_len, max_path - path_len, "/%s",
		               entry->d_name);
		if (ret <= 0 || ret >= max_path - path_len) {
			free(entry);
			free(path);
			return KNOT_EINVAL;
		}

		// Ignore directories inside the current directory.
		if (stat(path, &file_stat) == 0 && !S_ISREG(file_stat.st_mode)) {
			continue;
		}

		ret = conf_parse(args->conf, args->txn, path, true,
		                      args->incl_depth);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	free(entry);
	closedir(dir);
	free(path);

	return ret;
}
