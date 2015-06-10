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
	conf_check_t *args)
{
	const char *err_str = "invalid reference";

	const yp_item_t *parent = args->check->key1->var.r.ref;

	// Try to find the id in the referenced category.
	// Cannot use conf_raw_get as id is not stored in confdb directly!
	int ret = conf_db_get(args->conf, args->txn, parent->name, NULL,
	                      args->check->data, args->check->data_len, NULL);
	if (ret != KNOT_EOK) {
		*args->err_str = err_str;
	}

	return ret;
}

int check_modref(
	conf_check_t *args)
{
	const char *err_str = "invalid module reference";

	const yp_name_t *mod_name = (const yp_name_t *)args->check->data;
	const uint8_t *id = args->check->data + 1 + args->check->data[0];
	size_t id_len = args->check->data_len - 1 - args->check->data[0];

	// Try to find the module with id.
	// Cannot use conf_raw_get as id is not stored in confdb directly!
	int ret = conf_db_get(args->conf, args->txn, mod_name, NULL, id, id_len,
	                      NULL);
	if (ret != KNOT_EOK) {
		*args->err_str = err_str;
	}

	return ret;
}

int check_remote(
	conf_check_t *args)
{
	const char *err_str = "no remote address defined";

	conf_val_t addr = conf_rawid_get_txn(args->conf, args->txn, C_RMT,
	                                     C_ADDR, args->previous->id,
	                                     args->previous->id_len);
	if (conf_val_count(&addr) == 0) {
		*args->err_str = err_str;
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int check_zone(
	conf_check_t *args)
{
	const char *err_str = "slave zone with DNSSEC signing";

	conf_val_t master = conf_zone_get_txn(args->conf, args->txn,
	                                      C_MASTER, args->previous->id);
	conf_val_t dnssec = conf_zone_get_txn(args->conf, args->txn,
	                                      C_DNSSEC_SIGNING, args->previous->id);

	// DNSSEC signing is not possible with slave zone.
	if (conf_val_count(&master) > 0 && conf_bool(&dnssec)) {
		*args->err_str = err_str;
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

int include_file(
	conf_check_t *args)
{
	size_t max_path = 4096;
	char *path = malloc(max_path);
	if (path == NULL) {
		return KNOT_ENOMEM;
	}

	// Prepare absolute include path.
	int ret;
	if (args->check->data[0] == '/') {
		ret = snprintf(path, max_path, "%.*s",
		               (int)args->check->data_len, args->check->data);
	} else {
		const char *file_name = args->parser->file.name != NULL ?
		                        args->parser->file.name : "./";
		char *full_current_name = realpath(file_name, NULL);
		if (full_current_name == NULL) {
			free(path);
			return KNOT_ENOMEM;
		}

		ret = snprintf(path, max_path, "%s/%.*s",
		               dirname(full_current_name),
		               (int)args->check->data_len, args->check->data);
		free(full_current_name);
	}
	if (ret <= 0 || ret >= max_path) {
		free(path);
		return KNOT_ESPACE;
	}
	size_t path_len = ret;

	// Get file status.
	struct stat file_stat;
	if (stat(path, &file_stat) != 0) {
		free(path);
		return KNOT_EFILE;
	}

	// Process regular file.
	if (S_ISREG(file_stat.st_mode)) {
		ret = conf_parse(args->conf, args->txn, path, true,
		                 args->include_depth, args->previous);
		free(path);
		return ret;
	} else if (!S_ISDIR(file_stat.st_mode)) {
		free(path);
		return KNOT_EFILE;
	}

	// Process directory.
	DIR *dir = opendir(path);
	if (dir == NULL) {
		free(path);
		return KNOT_EFILE;
	}

	// Prepare own dirent structure (see NOTES in man readdir_r).
	size_t len = offsetof(struct dirent, d_name) +
	             fpathconf(dirfd(dir), _PC_NAME_MAX) + 1;
	struct dirent *entry = malloc(len);
	if (entry == NULL) {
		free(path);
		return KNOT_ENOMEM;
	}
	memset(entry, 0, len);

	ret = KNOT_EOK;

	int error;
	struct dirent *result = NULL;
	while ((error = readdir_r(dir, entry, &result)) == 0 && result != NULL) {
		// Skip names with leading dot.
		if (entry->d_name[0] == '.') {
			continue;
		}

		// Prepare included file absolute path.
		ret = snprintf(path + path_len, max_path - path_len, "/%s",
		               entry->d_name);
		if (ret <= 0 || ret >= max_path - path_len) {
			ret = KNOT_ESPACE;
			break;
		} else {
			ret = KNOT_EOK;
		}

		// Ignore directories inside the current directory.
		if (stat(path, &file_stat) == 0 && !S_ISREG(file_stat.st_mode)) {
			continue;
		}

		ret = conf_parse(args->conf, args->txn, path, true,
		                 args->include_depth, args->previous);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	if (error != 0) {
		ret = knot_map_errno();
	}

	free(entry);
	closedir(dir);
	free(path);

	return ret;
}
