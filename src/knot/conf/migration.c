/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/common/log.h"
#include "knot/conf/migration.h"
#include "knot/conf/confdb.h"
#include "contrib/files.h"
#include "contrib/macros.h"
#include "contrib/string.h"
#include "contrib/time.h"

/*
static void try_unset(conf_t *conf, knot_db_txn_t *txn, yp_name_t *key0, yp_name_t *key1)
{
	int ret = conf_db_unset(conf, txn, key0, key1, NULL, 0, NULL, 0, true);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		log_warning("conf, migration, failed to unset '%s%s%s' (%s)",
		            key0 + 1,
		            (key1 != NULL) ? "/"      : "",
		            (key1 != NULL) ? key1 + 1 : "",
		            knot_strerror(ret));
	}
}

#define check_set(conf, txn, key0, key1, id, id_len, data, data_len) \
	ret = conf_db_set(conf, txn, key0, key1, id, id_len, data, data_len); \
	if (ret != KNOT_EOK && ret != KNOT_CONF_EREDEFINE) { \
		log_error("conf, migration, failed to set '%s%s%s' (%s)", \
		          key0 + 1, \
		          (key1 != NULL) ? "/"      : "", \
		          (key1 != NULL) ? key1 + 1 : "", \
		          knot_strerror(ret)); \
		return ret; \
	}

static int migrate_(
	conf_t *conf,
	knot_db_txn_t *txn)
{
	return KNOT_EOK;
}
*/

int conf_migrate(
	conf_t *conf)
{
	return KNOT_EOK;
	/*
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_txn_t txn;
	int ret = conf->api->txn_begin(conf->db, &txn, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = migrate_(conf, &txn);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		return ret;
	}

	ret = conf->api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return conf_refresh_txn(conf);
	*/
}

static int move_files(const char *from_dir, const char *to_dir, const char *fname, const char *fname2)
{
	unsigned buf_len = MAX(strlen(from_dir), strlen(to_dir)) + MAX(strlen(fname), strlen(fname2)) + 2;
	char from[buf_len], to[buf_len];
	snprintf(from, buf_len, "%s/%s", from_dir, fname);
	snprintf(to, buf_len, "%s/%s", to_dir, fname);
	if (rename(from, to) != 0) {
		return knot_map_errno();
	}
	snprintf(from, buf_len, "%s/%s", from_dir, fname2);
	snprintf(to, buf_len, "%s/%s", to_dir, fname2);
	if (rename(from, to) != 0) {
		return knot_map_errno();
	}
	return KNOT_EOK;
}

int migrate_lmdb(
	const char *db_dir,
	bool named_db)
{
	if (db_dir == NULL) {
		return KNOT_EINVAL;
	}

	log_notice("database, incompatible '%s', migrating to LMDB version 1.x", db_dir);

#define MIGR_LOG(ret, msg, ...) if (ret != KNOT_EOK) { \
	log_error("database, " msg ", failed (%s)", ##__VA_ARGS__, knot_strerror(ret)); \
}

	struct timespec now_ts = { 0 };
	clock_gettime(CLOCK_REALTIME, &now_ts);
	knot_millis_t now_ms = knot_millis_from_timespec(&now_ts);

	int ret = KNOT_EOK;
	char *dump_file = sprintf_alloc("%s.%llu.export", db_dir, now_ms);
	char *back_dir = sprintf_alloc("%s.%llu.back", db_dir, now_ms);
	char *tmp_dir = sprintf_alloc("%s.%llu.tmp", db_dir, now_ms);
	if (dump_file == NULL || back_dir == NULL || tmp_dir == NULL) {
		ret = KNOT_ENOMEM;
	}
	if (ret == KNOT_EOK) {
		ret = knot_db_lmdb_dump(db_dir, dump_file, named_db);
		MIGR_LOG(ret, "exporting to '%s', LMDB version 0.9", dump_file);
	}
	if (ret == KNOT_EOK) {
		ret = make_dir(tmp_dir, LMDB_DIR_MODE, true);
		MIGR_LOG(ret, "creating temporary directory '%s'", tmp_dir);
	}
	if (ret == KNOT_EOK) {
		ret = make_dir(back_dir, LMDB_DIR_MODE, true);
		MIGR_LOG(ret, "creating backup directory '%s'", back_dir);
	}
	if (ret == KNOT_EOK) {
		ret = knot_db_lmdb_load(tmp_dir, dump_file);
		MIGR_LOG(ret, "importing to '%s'", tmp_dir);
	}
	if (ret == KNOT_EOK) {
		ret = move_files(db_dir, back_dir, "data.mdb", "lock.mdb");
		MIGR_LOG(ret, "moving previous database to '%s'", back_dir);
	}
	if (ret == KNOT_EOK) {
		ret = move_files(tmp_dir, db_dir, "data.mdb", "lock.mdb");
		MIGR_LOG(ret, "moving new database to '%s'", db_dir);
	}
	if (ret != KNOT_EOK) {
		remove_path(tmp_dir, false);
		remove_path(dump_file, false);
		log_error("database, migration of '%s' failed", db_dir);
	} else {
		log_notice("database, migration of '%s' successful", db_dir);
		log_notice("database, export stored in '%s', backup stored in '%s'",
		           dump_file, back_dir);
	}
	free(dump_file);
	free(back_dir);
	free(tmp_dir);
	return ret;
}
