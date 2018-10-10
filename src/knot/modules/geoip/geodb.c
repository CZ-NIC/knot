/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/modules/geoip/geodb.h"
#include "contrib/strtonum.h"
#include "contrib/string.h"

#if HAVE_MAXMINDDB
static const uint16_t type_map[] = {
	[GEODB_KEY_ID]  = MMDB_DATA_TYPE_UINT32,
	[GEODB_KEY_TXT] = MMDB_DATA_TYPE_UTF8_STRING
};
#endif

int parse_geodb_path(geodb_path_t *path, const char *input)
{
	if (path == NULL || input == NULL) {
		return -1;
	}

	// Parse optional type of key.
	path->type = GEODB_KEY_TXT;
	const char *delim = input;
	if (input[0] == '(') {
		delim = strchr(input, ')');
		if (delim == NULL) {
			return -1;
		}
		input++;
		char *type = sprintf_alloc("%.*s", delim - input, input);
		const knot_lookup_t *table = knot_lookup_by_name(geodb_key_types, type);
		free(type);
		if (table == NULL) {
			return -1;
		}
		path->type = table->id;
		input = delim + 1;
	}

	// Parse the path.
	uint16_t len = 0;
	while (1) {
		delim = strchr(input, '/');
		if (delim == NULL) {
			delim = input + strlen(input);
		}
		path->path[len] = malloc(delim - input + 1);
		if (path->path[len] == NULL) {
			return -1;
		}
		memcpy(path->path[len], input, delim - input);
		path->path[len][delim - input] = '\0';
		len++;
		if (*delim == 0 || len == GEODB_MAX_PATH_LEN) {
			break;
		}
		input = delim + 1;
	}

	return 0;
}

int parse_geodb_data(const char *input, void **geodata, uint32_t *geodata_len,
                     uint8_t *geodepth, geodb_path_t *path, uint16_t path_cnt)
{
	for (uint16_t i = 0; i < path_cnt; i++) {
		const char *delim = strchr(input, ';');
		if (delim == NULL) {
			delim = input + strlen(input);
		}
		uint16_t key_len = delim - input;
		if (key_len > 0 && !(key_len == 1 && *input == '*')) {
			*geodepth = i + 1;
			switch (path[i].type) {
			case GEODB_KEY_TXT:
				geodata[i] = malloc(key_len + 1);
				if (geodata[i] == NULL) {
					return -1;
				}
				memcpy(geodata[i], input, key_len);
				((char *)geodata[i])[key_len] = '\0';
				geodata_len[i] = key_len;
				break;
			case GEODB_KEY_ID:
				geodata[i] = malloc(sizeof(uint32_t));
				if (geodata[i] == NULL) {
					return -1;
				}
				if (str_to_u32(input, (uint32_t *)geodata[i]) != KNOT_EOK) {
					return -1;
				}
				geodata_len[i] = sizeof(uint32_t);
				break;
			default:
				assert(0);
				return -1;
			}
		}
		if (*delim == '\0') {
			break;
		}
		input = delim + 1;
	}

	return 0;
}

bool geodb_available(void)
{
#if HAVE_MAXMINDDB
	return true;
#else
	return false;
#endif
}

geodb_t *geodb_open(const char *filename)
{
#if HAVE_MAXMINDDB
	MMDB_s *db = calloc(1, sizeof(MMDB_s));
	if (db == NULL) {
		return NULL;
	}
	int mmdb_error = MMDB_open(filename, MMDB_MODE_MMAP, db);
	if (mmdb_error != MMDB_SUCCESS) {
		free(db);
		return NULL;
	}
	return db;
#else
	return NULL;
#endif
}

void geodb_close(geodb_t *geodb)
{
#if HAVE_MAXMINDDB
	MMDB_close(geodb);
#endif
}

int geodb_query(geodb_t *geodb, geodb_data_t *entries, struct sockaddr *remote,
                geodb_path_t *paths, uint16_t path_cnt, uint16_t *netmask)
{
#if HAVE_MAXMINDDB
	int mmdb_error = 0;
	MMDB_lookup_result_s res;
	res = MMDB_lookup_sockaddr(geodb, remote, &mmdb_error);
	if (mmdb_error != MMDB_SUCCESS || !res.found_entry) {
		return -1;
	}

	// Save netmask.
	*netmask = res.netmask;

	for (uint16_t i = 0; i < path_cnt; i++) {
		// Get the value of the next key.
		mmdb_error = MMDB_aget_value(&res.entry, &entries[i], (const char *const*)paths[i].path);
		if (mmdb_error != MMDB_SUCCESS && mmdb_error != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
			return -1;
		}
		if (mmdb_error == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR || !entries[i].has_data) {
			entries[i].has_data = false;
			continue;
		}
		// Check the type.
		if (entries[i].type != type_map[paths[i].type]) {
			entries[i].has_data = false;
			continue;
		}
	}
	return 0;
#else
	return -1;
#endif
}

bool remote_in_geo(void **geodata, uint32_t *geodata_len, uint16_t geodepth, geodb_data_t *entries)
{
#if HAVE_MAXMINDDB
	for (int i = 0; i < geodepth; i++) {
		// Nothing to do if current geodata do not specify this key.
		if (geodata[i] == NULL) {
			continue;
		}
		if (!entries[i].has_data) {
			return false;
		}
		switch (entries[i].type) {
		case MMDB_DATA_TYPE_UTF8_STRING:
			if (geodata_len[i] != entries[i].data_size ||
			    memcmp(geodata[i], entries[i].utf8_string, geodata_len[i]) != 0) {
				return false;
			}
			break;
		case MMDB_DATA_TYPE_UINT32:
			if (*((uint32_t *)geodata[i]) != entries[i].uint32) {
				return false;
			}
			break;
		default:
			return false;
		}
	}
	return true;
#else
	return false;
#endif
}
