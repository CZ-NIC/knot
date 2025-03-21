/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
#define geodb_data_t	char
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
	{ GEODB_KEY_TXT, "" },
	{ 0, NULL }
};

typedef struct {
	geodb_key_type_t type;
	char *path[GEODB_MAX_PATH_LEN + 1]; // MMDB_aget_value() requires last member to be NULL.
} geodb_path_t;

int parse_geodb_path(geodb_path_t *path, const char *input);

int parse_geodb_data(const char *input, void **geodata, uint32_t *geodata_len,
                     uint8_t *geodepth, geodb_path_t *path, uint16_t path_cnt);

bool geodb_available(void);

geodb_t *geodb_open(const char *filename);

void geodb_close(geodb_t *geodb);

int geodb_query(geodb_t *geodb, geodb_data_t *entries, struct sockaddr *remote,
                geodb_path_t *paths, uint16_t path_cnt, uint16_t *netmask);

void geodb_fill_geodata(geodb_data_t *entries, uint16_t path_cnt,
                        void **geodata, uint32_t *geodata_len, uint8_t *geodepth);
