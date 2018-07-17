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

#pragma once

#include <libknot/libknot.h>
#if HAVE_MAXMINDDB
#include <maxminddb.h>
#endif

#if HAVE_MAXMINDDB
#define geodb_t		MMDB_s
#define geodb_data_t	MMDB_entry_data_s
#else
#define geodb_t		void
#define geodb_data_t	void
#endif

// MaxMind DB related constants.
#define GEODB_MAX_PATH_LEN 8
#define GEODB_MAX_DEPTH 8

typedef enum {
	GEODB_KEY_ID,
	GEODB_KEY_TXT
} geodb_key_type_t;

static const knot_lookup_t geodb_key_types[] = {
	{ GEODB_KEY_ID, "id" },
	{ GEODB_KEY_TXT, "" }
};

typedef struct {
	geodb_key_type_t type;
	char *path[GEODB_MAX_PATH_LEN + 1]; // MMDB_aget_value() requires last member to be NULL.
} geodb_path_t;

int parse_geodb_path(geodb_path_t *path, const char *input);

int parse_geodb_data(const char *input, void **geodata, uint32_t *geodata_len,
                     uint8_t *geodepth, geodb_path_t *path, uint16_t path_cnt);

geodb_t *geodb_open(const char *filename);

geodb_data_t *geodb_alloc_entries(uint16_t count);

void geodb_close(geodb_t *geodb);

int geodb_query(geodb_t *geodb, geodb_data_t *entries, struct sockaddr *remote,
                geodb_path_t *paths, uint16_t path_cnt, uint16_t *netmask);

bool remote_in_geo(void **geodata, uint32_t *geodata_len, uint16_t geodepth, geodb_data_t *entries);
