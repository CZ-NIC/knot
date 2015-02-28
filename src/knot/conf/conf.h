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
/*!
 * \file
 *
 * Server configuration and API.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include <stdlib.h>
#include <sys/socket.h>

#include "knot/conf/scheme.h"
#include "libknot/internal/lists.h"
#include "libknot/internal/namedb/namedb.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/yparser/ypscheme.h"

#define CONF_XFERS		10
#define CONF_DEFAULT_ID		((uint8_t *)"\x08""default\0")
#define CONF_DEFAULT_FILE	(CONFIG_DIR "/knot.conf")
//#define CONF_DEFAULT_DBDIR	(STORAGE_DIR "/confdb")

typedef struct {
	const struct namedb_api *api;
	yp_item_t *scheme;
	mm_ctx_t *mm;
	namedb_t *db;
	// Read-only transaction for config access.
	namedb_txn_t read_txn;
	// For automatic NSID or CH ident.
	char *hostname;
	// For reload if started with config file.
	char *filename;
	// Temporary database path.
	char *tmp_dir;
	// List of active query modules.
	list_t query_modules;
	// Default query modules plan.
	struct query_plan *query_plan;
} conf_t;

typedef struct {
	struct sockaddr_storage addr;
	struct sockaddr_storage via;
	knot_tsig_key_t key;
} conf_remote_t;

typedef struct {
	const yp_item_t *item;
	const uint8_t *blob;
	size_t blob_len;
	// Public items.
	const uint8_t *data;
	size_t len;
	int code; // Return code.
} conf_val_t;

typedef struct {
	const yp_item_t *item;
	namedb_iter_t *iter;
	uint8_t key0_code;
	// Public items.
	int code; // Return code.
} conf_iter_t;

typedef struct {
	yp_name_t *name;
	uint8_t *data;
	size_t len;
} conf_mod_id_t;

extern conf_t *s_conf;

static inline conf_t* conf(void) {
	return s_conf;
}

int conf_new(
	conf_t **conf,
	const yp_item_t *scheme,
	const char *db_dir
);

int conf_clone(
	conf_t **conf
);

int conf_post_open(
	conf_t *conf
);

void conf_update(
	conf_t *conf
);

void conf_free(
	conf_t *conf,
	bool is_clone
);

int conf_activate_modules(
	conf_t *conf,
	knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan
);

void conf_deactivate_modules(
	conf_t *conf,
	list_t *query_modules,
	struct query_plan *query_plan
);

int conf_parse(
	conf_t *conf,
	namedb_txn_t *txn,
	const char *input,
	bool is_file,
	size_t *incl_depth
);

int conf_import(
	conf_t *conf,
	const char *input,
	bool is_file
);

int conf_export(
	conf_t *conf,
	const char *file_name,
	yp_style_t style
);

/*****************/

conf_val_t conf_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name
);

conf_val_t conf_id_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	conf_val_t *id
);

conf_val_t conf_mod_get(
	conf_t *conf,
	const yp_name_t *key1_name,
	const conf_mod_id_t *mod_id
);

conf_val_t conf_zone_get(
	conf_t *conf,
	const yp_name_t *key1_name,
	const knot_dname_t *dname
);

conf_val_t conf_default_get(
	conf_t *conf,
	const yp_name_t *key1_name
);

size_t conf_id_count(
	conf_t *conf,
	const yp_name_t *key0_name
);

conf_iter_t conf_iter(
	conf_t *conf,
	const yp_name_t *key0_name
);

void conf_iter_next(
	conf_t *conf,
	conf_iter_t *iter
);

conf_val_t conf_iter_id(
	conf_t *conf,
	conf_iter_t *iter
);

void conf_iter_finish(
	conf_t *conf,
	conf_iter_t *iter
);

size_t conf_val_count(
	conf_val_t *val
);

void conf_val_next(
	conf_val_t *val
);

int64_t conf_int(
	conf_val_t *val
);

bool conf_bool(
	conf_val_t *val
);

unsigned conf_opt(
	conf_val_t *val
);

const char* conf_str(
	conf_val_t *val
);

char* conf_abs_path(
	conf_val_t *val,
	const char *base_dir
);

const knot_dname_t* conf_dname(
	conf_val_t *val
);

conf_mod_id_t* conf_mod_id(
	conf_val_t *val
);

void conf_free_mod_id(
	conf_mod_id_t *mod_id
);

struct sockaddr_storage conf_addr(
	conf_val_t *val,
	const char *sock_base_dir
);

struct sockaddr_storage conf_net(
	conf_val_t *val,
	unsigned *prefix_length
);

void conf_data(
	conf_val_t *val
);

char* conf_zonefile(
	conf_t *conf,
	const knot_dname_t *zone
);

char* conf_journalfile(
	conf_t *conf,
	const knot_dname_t *zone
);

size_t conf_udp_threads(
	conf_t *conf
);

size_t conf_tcp_threads(
	conf_t *conf
);

int conf_bg_threads(
	conf_t *conf
);

void conf_user(
	conf_t *conf,
	int *uid,
	int *gid
);

conf_remote_t conf_remote(
	conf_t *conf,
	conf_val_t *id
);
