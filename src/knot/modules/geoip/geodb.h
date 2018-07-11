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

#if HAVE_MAXMINDDB
#include <maxminddb.h>
#endif

enum geodb_key {
	CONTINENT,
	COUNTRY,
	CITY,
	ISP
};

// MaxMind DB related constants.
#define MAX_PATH_LEN 4
#define GEODB_KEYS 4

typedef struct {
	const char *path[MAX_PATH_LEN];
}mmdb_path_t;

mmdb_path_t paths[] = {
	{{"continent", "code", NULL}},
	{{"country", "iso_code", NULL}},
	{{"city", "names", "en", NULL}},
	{{"isp", NULL}}
};

void *geodb_open(const char *filename)
{
#if HAVE_MAXMINDDB
	MMDB_s *db = calloc(1, sizeof(MMDB_s));
	if (db == NULL) {
		return NULL;
	}
	int mmdb_error = MMDB_open(filename, MMDB_MODE_MMAP, db);
	if (mmdb_error != MMDB_SUCCESS) {
		return NULL;
	}
	return (void *)db;
#endif
	return NULL;
}

void geodb_close(void *geodb)
{
#if HAVE_MAXMINDDB
	MMDB_s *db = (MMDB_s *)geodb;
	MMDB_close(db);
#endif
}

int geodb_query(void *geodb, struct sockaddr *remote,
                enum geodb_key *keys, uint16_t keyc,
                char **geodata, uint32_t *geodata_len, uint16_t *netmask)
{
#if HAVE_MAXMINDDB
	MMDB_s *db = (MMDB_s *)geodb;
	int mmdb_error = 0;
	MMDB_lookup_result_s res;
	res = MMDB_lookup_sockaddr(db, remote, &mmdb_error);
	if (mmdb_error != MMDB_SUCCESS || !res.found_entry) {
		return -1;
	}

	// Save netmask.
	*netmask = res.netmask;

	MMDB_entry_data_s entry;
	// Set the remote's geo information.
	for (uint16_t i = 0; i < keyc; i++) {
		enum geodb_key key = keys[i];
		geodata[key] = NULL;
		mmdb_error = MMDB_aget_value(&res.entry, &entry, paths[key].path);
		if (mmdb_error != MMDB_SUCCESS &&
			mmdb_error != MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR) {
			return -1;
		}
		if (mmdb_error == MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR ||
			!entry.has_data || entry.type != MMDB_DATA_TYPE_UTF8_STRING) {
			continue;
		}
		geodata[key] = (char *)entry.utf8_string;
		geodata_len[key] = entry.data_size;
	}

	return 0;
#endif
	return -1;
}
