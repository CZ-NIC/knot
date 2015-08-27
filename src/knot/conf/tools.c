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
#include <glob.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#ifndef PATH_MAX
  #define PATH_MAX 4096
#endif

#include "knot/conf/tools.h"
#include "knot/conf/conf.h"
#include "knot/conf/confdb.h"
#include "knot/conf/scheme.h"
#include "knot/common/log.h"
#include "libknot/errcode.h"
#include "libknot/internal/utils.h"
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

int edns_opt_to_bin(
	char const *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len)
{
	char *suffix = NULL;
	unsigned long number = strtoul(txt, &suffix, 10);

	// Check for "code:[value]" format.
	if (suffix <= txt || *suffix != ':' || number > UINT16_MAX) {
		return KNOT_EINVAL;
	}

	// Store the option code.
	uint16_t code = number;
	if (*bin_len < sizeof(code)) {
		return KNOT_ESPACE;
	}
	wire_write_u16(bin, code);
	bin += sizeof(code);

	// Prepare suffix input (behind colon character).
	size_t txt_suffix_len = txt_len - (suffix - txt) - 1;
	size_t bin_suffix_len = *bin_len - sizeof(code);
	suffix++;

	// Convert suffix data.
	int ret = hex_text_to_bin(suffix, txt_suffix_len, bin, &bin_suffix_len);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set output data length.
	*bin_len = sizeof(code) + bin_suffix_len;

	return KNOT_EOK;
}

int edns_opt_to_txt(
	uint8_t const *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len)
{
	uint16_t code = wire_read_u16(bin);

	// Write option code part.
	int code_len = snprintf(txt, *txt_len, "%u:", code);
	if (code_len <= 0 || code_len >= *txt_len) {
		return KNOT_ESPACE;
	}

	size_t data_len = *txt_len - code_len;

	// Write possible option data part.
	int ret = hex_text_to_txt(bin + sizeof(code), bin_len - sizeof(code),
	                          txt + code_len, &data_len);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Set output text length.
	*txt_len = code_len + data_len;

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

static int glob_error(
	const char *epath,
	int eerrno)
{
	CONF_LOG(LOG_WARNING, "failed to access '%s' (%s)", epath,
	         knot_strerror(knot_map_errno_code(eerrno)));

	return 0;
}

int include_file(
	conf_check_t *args)
{
	glob_t glob_buf = { 0 };
	int ret;

	char *path = malloc(PATH_MAX);
	if (path == NULL) {
		return KNOT_ENOMEM;
	}

	// Prepare absolute include path.
	if (args->check->data[0] == '/') {
		ret = snprintf(path, PATH_MAX, "%.*s",
		               (int)args->check->data_len, args->check->data);
	} else {
		const char *file_name = args->parser->file.name != NULL ?
		                        args->parser->file.name : "./";
		char *full_current_name = realpath(file_name, NULL);
		if (full_current_name == NULL) {
			ret = KNOT_ENOMEM;
			goto include_error;
		}

		ret = snprintf(path, PATH_MAX, "%s/%.*s",
		               dirname(full_current_name),
		               (int)args->check->data_len, args->check->data);
		free(full_current_name);
	}
	if (ret <= 0 || ret >= PATH_MAX) {
		ret = KNOT_ESPACE;
		goto include_error;
	}

	// Evaluate include pattern.
	ret = glob(path, 0, glob_error, &glob_buf);
	if (ret != 0) {
		ret = KNOT_EFILE;
		goto include_error;
	}

	// Process glob result.
	for (size_t i = 0; i < glob_buf.gl_pathc; i++) {
		// Get file status.
		struct stat file_stat;
		if (stat(glob_buf.gl_pathv[i], &file_stat) != 0) {
			CONF_LOG(LOG_WARNING, "failed to get file status for '%s'",
			         glob_buf.gl_pathv[i]);
			continue;
		}

		// Ignore directory or non-regular file.
		if (S_ISDIR(file_stat.st_mode)) {
			continue;
		} else if (!S_ISREG(file_stat.st_mode)) {
			CONF_LOG(LOG_WARNING, "invalid include file '%s'",
			         glob_buf.gl_pathv[i]);
			continue;
		}

		// Include regular file.
		ret = conf_parse(args->conf, args->txn, glob_buf.gl_pathv[i],
		                 true, args->include_depth, args->previous);
		if (ret != KNOT_EOK) {
			goto include_error;
		}
	}

	ret = KNOT_EOK;
include_error:
	globfree(&glob_buf);
	free(path);

	return ret;
}
