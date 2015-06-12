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
 * Server configuration interface.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include <sys/socket.h>

#include "knot/conf/base.h"
#include "knot/conf/scheme.h"

/*! Configuration remote getter output. */
typedef struct {
	/*! Target socket address. */
	struct sockaddr_storage addr;
	/*! Local outgoing socket address. */
	struct sockaddr_storage via;
	/*! TSIG key. */
	knot_tsig_key_t key;
} conf_remote_t;

/*! Configuration getter output. */
typedef struct {
	/*! Item description. */
	const yp_item_t *item;
	/*! Whole data (can be array). */
	const uint8_t *blob;
	/*! Whole data length. */
	size_t blob_len;
	// Public items.
	/*! Current single data. */
	const uint8_t *data;
	/*! Current single data length. */
	size_t len;
	/*! Value getter return code. */
	int code;
} conf_val_t;

/*! Configuration section iterator. */
typedef struct {
	/*! Item description. */
	const yp_item_t *item;
	/*! Namedb iterator. */
	namedb_iter_t *iter;
	/*! Key0 database code. */
	uint8_t key0_code;
	// Public items.
	/*! Iterator return code. */
	int code;
} conf_iter_t;

/*! Configuration module getter output. */
typedef struct {
	/*! Module name. */
	yp_name_t *name;
	/*! Module id data. */
	uint8_t *data;
	/*! Module id data length. */
	size_t len;
} conf_mod_id_t;

conf_val_t conf_get_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name
);
static inline conf_val_t conf_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name)
{
	return conf_get_txn(conf, &conf->read_txn, key0_name, key1_name);
}

conf_val_t conf_rawid_get_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	const uint8_t *id,
	size_t id_len
);
static inline conf_val_t conf_rawid_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	const uint8_t *id,
	size_t id_len)
{
	return conf_rawid_get_txn(conf, &conf->read_txn, key0_name, key1_name,
	                          id, id_len);
}

conf_val_t conf_id_get_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	conf_val_t *id
);
static inline conf_val_t conf_id_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	conf_val_t *id)
{
	return conf_id_get_txn(conf, &conf->read_txn, key0_name, key1_name, id);
}

conf_val_t conf_mod_get_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key1_name,
	const conf_mod_id_t *mod_id
);
static inline conf_val_t conf_mod_get(
	conf_t *conf,
	const yp_name_t *key1_name,
	const conf_mod_id_t *mod_id)
{
	return conf_mod_get_txn(conf, &conf->read_txn, key1_name, mod_id);
}

conf_val_t conf_zone_get_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key1_name,
	const knot_dname_t *dname
);
static inline conf_val_t conf_zone_get(
	conf_t *conf,
	const yp_name_t *key1_name,
	const knot_dname_t *dname)
{
	return conf_zone_get_txn(conf, &conf->read_txn, key1_name, dname);
}

conf_val_t conf_default_get_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key1_name
);
static inline conf_val_t conf_default_get(
	conf_t *conf,
	const yp_name_t *key1_name)
{
	return conf_default_get_txn(conf, &conf->read_txn, key1_name);
}

size_t conf_id_count_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0_name
);
static inline size_t conf_id_count(
	conf_t *conf,
	const yp_name_t *key0_name)
{
	return conf_id_count_txn(conf, &conf->read_txn, key0_name);
}

conf_iter_t conf_iter_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0_name
);
static inline conf_iter_t conf_iter(
	conf_t *conf,
	const yp_name_t *key0_name)
{
	return conf_iter_txn(conf, &conf->read_txn, key0_name);
}

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

const knot_dname_t* conf_dname(
	conf_val_t *val
);

void conf_data(
	conf_val_t *val
);

struct sockaddr_storage conf_addr(
	conf_val_t *val,
	const char *sock_base_dir
);

struct sockaddr_storage conf_net(
	conf_val_t *val,
	int *prefix_length
);

char* conf_abs_path(
	conf_val_t *val,
	const char *base_dir
);

conf_mod_id_t* conf_mod_id(
	conf_val_t *val
);

void conf_free_mod_id(
	conf_mod_id_t *mod_id
);

char* conf_zonefile_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const knot_dname_t *zone
);
static inline char* conf_zonefile(
	conf_t *conf,
	const knot_dname_t *zone)
{
	return conf_zonefile_txn(conf, &conf->read_txn, zone);
}

char* conf_journalfile_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	const knot_dname_t *zone
);
static inline char* conf_journalfile(
	conf_t *conf,
	const knot_dname_t *zone)
{
	return conf_journalfile_txn(conf, &conf->read_txn, zone);
}

size_t conf_udp_threads_txn(
	conf_t *conf,
	namedb_txn_t *txn
);
static inline size_t conf_udp_threads(
	conf_t *conf)
{
	return conf_udp_threads_txn(conf, &conf->read_txn);
}

size_t conf_tcp_threads_txn(
	conf_t *conf,
	namedb_txn_t *txn
);
static inline size_t conf_tcp_threads(
	conf_t *conf)
{
	return conf_tcp_threads_txn(conf, &conf->read_txn);
}

size_t conf_bg_threads_txn(
	conf_t *conf,
	namedb_txn_t *txn
);
static inline size_t conf_bg_threads(
	conf_t *conf)
{
	return conf_bg_threads_txn(conf, &conf->read_txn);
}

int conf_user_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	int *uid,
	int *gid
);
static inline int conf_user(
	conf_t *conf,
	int *uid,
	int *gid)
{
	return conf_user_txn(conf, &conf->read_txn, uid, gid);
}

conf_remote_t conf_remote_txn(
	conf_t *conf,
	namedb_txn_t *txn,
	conf_val_t *id,
	size_t index
);
static inline conf_remote_t conf_remote(
	conf_t *conf,
	conf_val_t *id,
	size_t index)
{
	return conf_remote_txn(conf, &conf->read_txn, id, index);

}

/*! @} */
