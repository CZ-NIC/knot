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

#include<libknot/libknot.h>
#if HAVE_MAXMINDDB
#include <maxminddb.h>
#endif

// MaxMind DB related constants.
#define GEODB_MAX_PATH_LEN 8
#define GEODB_MAX_DEPTH 8

typedef enum {
	GEODB_KEY_ID,
	GEODB_KEY_TXT
} geodb_key_type_t;

static const knot_lookup_t geodb_key_types[] =  {
	{ GEODB_KEY_ID, "id" },
	{ GEODB_KEY_TXT, "" }
};

typedef struct {
	geodb_key_type_t type;
	char *path[GEODB_MAX_PATH_LEN];
}geodb_path_t;

int parse_geodb_path(geodb_path_t *path, char *input);

int parse_geodata(void **geodata, uint32_t *geodata_len,
                  geodb_path_t *path, uint16_t path_cnt);

void *geodb_open(const char *filename);

void *geodb_alloc_entries(uint16_t count);

void geodb_close(void *geodb);

int geodb_query(void *geodb, void *entries, struct sockaddr *remote,
                geodb_path_t *paths, uint16_t path_cnt, uint16_t *netmask);

bool remote_in_geo(void **geodata, uint32_t *geodata_len, uint16_t geodepth, void *entries);
