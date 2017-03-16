/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <limits.h>
#include <sys/stat.h>
#include <stdarg.h>

#include "knot/journal/journal.h"
#include "knot/zone/serial.h"
#include "knot/common/log.h"
#include "contrib/files.h"
#include "contrib/endian.h"

/*! \brief Journal version. */
#define JOURNAL_VERSION	"1.0"
/*! \brief Changeset chunk size. */
#define CHUNK_MAX	(70 * 1024)
/*! \brief Max number of concurrent DB readers. */
#define JOURNAL_MAX_READERS 630

/*! \brief Various metadata DB key strings. Also hardcoded in macro txn_commit()! */
#define MDKEY_GLOBAL_VERSION			"version"
#define MDKEY_GLOBAL_JOURNAL_COUNT		"journal_count"
#define MDKEY_GLOBAL_LAST_TOTAL_OCCUPIED	"last_total_occupied"
#define MDKEY_GLOBAL_LAST_INSERTER_ZONE		"last_inserter_zone"
#define MDKEY_PERZONE_OCCUPIED			"occupied"
#define MDKEY_PERZONE_FLAGS			"flags"

/*! \brief The number of unused bytes in DB key. */
#define DB_KEY_UNUSED_ZERO (4)

/*! \brief Metadata inserted on the beginning of each chunk:
 * uint32_t serial_to + uint32_t chunk_count + 24B unused */
#define JOURNAL_HEADER_SIZE (32)

enum {
	LAST_FLUSHED_VALID  = 1 << 0, /* "last flush is valid" flag. */
	SERIAL_TO_VALID     = 1 << 1, /* "last serial_to is valid" flag. */
	MERGED_SERIAL_VALID = 1 << 2, /* "serial_from" of merged changeset. */
	DIRTY_SERIAL_VALID  = 1 << 3, /* "dirty_serial" is present in the DB. */
};

static bool journal_flush_allowed(journal_t *j) {
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, j->zone);
	return conf_int(&val) >= 0;
}

static bool journal_merge_allowed(journal_t *j) {
	return !journal_flush_allowed(j); // TODO think of other behaviour, e.g. setting
}

static size_t journal_max_usage(journal_t *j)
{
	conf_val_t val = conf_zone_get(conf(), C_MAX_JOURNAL_USAGE, j->zone);
	return conf_int(&val);
}

static size_t journal_max_changesets(journal_t *j)
{
	conf_val_t val = conf_zone_get(conf(), C_MAX_JOURNAL_DEPTH, j->zone);
	return conf_int(&val);
}

static float journal_tofree_factor(journal_t *j)
{
	return 2.0f;
}

static float journal_minfree_factor(journal_t *j)
{
	return 0.33f;
}

static float journal_max_txn(journal_t *j)
{
	return 0.05f;
}

/*
 * ***************************** PART I *******************************
 *
 *  Transaction manipulation functions
 *
 * ********************************************************************
 */

typedef struct {
	uint32_t first_serial;    // Serial_from of the first changeset.
	uint32_t last_serial;     // Serial_from of the last changeset.
	uint32_t last_serial_to;  // Serial_to of the last changeset.
	uint32_t last_flushed;    // Serial_from of the last flushed (or merged) chengeset.
	uint32_t merged_serial;   // "serial_from" of merged changeset.
	uint32_t dirty_serial;    // Serial_from of an incompletely inserted changeset which shall be deleted (see DB_MAX_INSERT_TXN).
	uint32_t changeset_count; // Number of changesets in this journal.
	uint32_t flags;           // LAST_FLUSHED_VALID, SERIAL_TO_VALID, MERGED_SERIAL_VALID.
} metadata_t;

typedef struct {
	journal_t *j;
	knot_db_txn_t *txn;
	int ret;

	bool is_rw;

	knot_db_iter_t *iter;

	knot_db_val_t key;
	knot_db_val_t val;
	uint8_t key_raw[512];

	metadata_t shadow_md;
} txn_t;

static void md_get(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint64_t *res);
static void md_get32(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint32_t *res);
static void md_set(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint64_t val);
static void md_set32(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint32_t val);

static void txn_init(txn_t *txn, knot_db_txn_t *db_txn, journal_t *j)
{
	txn->j = j;
	txn->txn = db_txn;
	txn->ret = KNOT_ESEMCHECK;
	txn->iter = NULL;
	txn->key.len = 0;
	txn->key.data = &txn->key_raw;
	txn->val.len = 0;
	txn->val.data = NULL;
}

#define local_txn_t(txn_name, journal) \
	knot_db_txn_t __db_txn_ ## txn_name; \
	txn_t __local_txn_ ## txn_name; \
	txn_t *txn_name = &__local_txn_ ## txn_name; \
	txn_init(txn_name, &__db_txn_ ## txn_name, (journal))

/*
 * Structure of the DB key:
 * Metadata:
 * | [ zone_name | \0 ] | unused zero 4B | metadata_key | \0 |
 *
 * Changeset:
 * | zone_name | \0 | unused zero 4B | (be32)serial_from | (be32)chunk_index |
 *
 * Structure of the changeset:
 * | (be32)serial_to | (be32)#of_chunks | unused zero 24B | serialized_changeset...
 *
 */

static void txn_key_str(txn_t *txn, const knot_dname_t *zone, const char *key)
{
	size_t zone_size = 0;
	if (zone != NULL) zone_size = knot_dname_size(zone);
	txn->key.len = zone_size + DB_KEY_UNUSED_ZERO + strlen(key) + 1;
	if (txn->key.len > 512) {
		txn->ret = KNOT_ERROR;
		return;
	}
	if (zone != NULL) memcpy(txn->key.data, zone, zone_size);
	memset(txn->key.data + zone_size, 0, DB_KEY_UNUSED_ZERO);
	strcpy(txn->key.data + zone_size + DB_KEY_UNUSED_ZERO, key);
}

static void txn_key_2u32(txn_t *txn, const knot_dname_t *zone, uint32_t key1, uint32_t key2)
{
	size_t zone_size = 0;
	if (zone != NULL) zone_size = knot_dname_size(zone);
	txn->key.len = zone_size + DB_KEY_UNUSED_ZERO + 2*sizeof(uint32_t);
	if (txn->key.len > 512) {
		txn->ret = KNOT_ERROR;
		return;
	}
	if (zone != NULL) memcpy(txn->key.data, zone, zone_size);
	memset(txn->key.data + zone_size, 0, DB_KEY_UNUSED_ZERO);
	uint32_t key_be1 = htobe32(key1);
	uint32_t key_be2 = htobe32(key2);
	memcpy(txn->key.data + zone_size + DB_KEY_UNUSED_ZERO, &key_be1, sizeof(uint32_t));
	memcpy(txn->key.data + zone_size + DB_KEY_UNUSED_ZERO + sizeof(uint32_t),
	       &key_be2, sizeof(uint32_t));
}

static int txn_cmpkey(txn_t *txn, knot_db_val_t *key2)
{
	if (txn->key.len != key2->len) {
		return (txn->key.len < key2->len ? -1 : 1);
	}
	if (key2->len == 0) {
		return 0;
	}
	return memcmp(txn->key.data, key2->data, key2->len);
}

static void txn_val_u64(txn_t *txn, uint64_t *res)
{
	if (txn->ret != KNOT_EOK) {
		return;
	}
	uint32_t beval32;
	uint64_t beval;
	switch (txn->val.len) {
	case sizeof(uint32_t):
		memcpy(&beval32, (uint32_t *)txn->val.data, sizeof(beval32));
		*res = (uint64_t)be32toh(beval32);
		break;
	case sizeof(uint64_t):
		memcpy(&beval, (uint64_t *)txn->val.data, sizeof(beval));
		*res = be64toh(beval);
		break;
	default:
		txn->ret = KNOT_EMALF;
	}
}

#define txn_begin_md(md) md_get32(txn, txn->j->zone, #md, &txn->shadow_md.md)
#define txn_commit_md(md) md_set32(txn, txn->j->zone, #md, txn->shadow_md.md)

#define txn_check(txn) if ((txn)->ret != KNOT_EOK) return
#define txn_check_ret(txn) if ((txn)->ret != KNOT_EOK) return ((txn)->ret)
#define txn_ret(txn) return ((txn)->ret == KNOT_ESEMCHECK ? KNOT_EOK : (txn)->ret)

#define txn_finished_ok(txn) ((txn)->ret == KNOT_ESEMCHECK || (txn)->ret == KNOT_EOK)

static void txn_begin(txn_t *txn, bool write_allowed)
{
	if (txn->ret == KNOT_EOK) {
		txn->ret = KNOT_EINVAL;
	}
	if (txn->ret != KNOT_ESEMCHECK) {
		return;
	}

	txn->ret = txn->j->db->db_api->txn_begin(txn->j->db->db, txn->txn,
	                                         (write_allowed ? 0 : KNOT_DB_RDONLY));

	txn->is_rw = write_allowed;

	txn_begin_md(first_serial);
	txn_begin_md(last_serial);
	txn_begin_md(last_serial_to);
	txn_begin_md(last_flushed);
	txn_begin_md(merged_serial);
	txn_begin_md(dirty_serial);
	txn_begin_md(changeset_count);
	txn_begin_md(flags);
}

static void txn_find_force(txn_t *txn)
{
	if (txn->ret == KNOT_EOK) {
		txn->ret = txn->j->db->db_api->find(txn->txn, &txn->key, &txn->val, 0);
	}
}

static int txn_find(txn_t *txn)
{
	if (txn->ret != KNOT_EOK) {
		return 0;
	}
	txn_find_force(txn);
	if (txn->ret == KNOT_ENOENT) {
		txn->ret = KNOT_EOK;
		return 0;
	}
	return (txn->ret == KNOT_EOK ? 1 : 0);
}

static void txn_insert(txn_t *txn)
{
	if (txn->ret == KNOT_EOK) {
		txn->ret = txn->j->db->db_api->insert(txn->txn, &txn->key, &txn->val, 0);
	}
}

static void txn_del(txn_t *txn)
{
	if (txn->ret == KNOT_EOK) {
		txn->ret = txn->j->db->db_api->del(txn->txn, &txn->key);
	}
}

static void txn_iter_begin(txn_t *txn)
{
	txn_check(txn);
	txn->iter = txn->j->db->db_api->iter_begin(txn->txn, KNOT_DB_FIRST);
	if (txn->iter == NULL) {
		txn->ret = KNOT_ENOMEM;
	}
}

#define txn_check_iter if (txn->iter == NULL && txn->ret == KNOT_EOK) txn->ret = KNOT_EINVAL; \
                       if (txn->ret != KNOT_EOK) return;

static void txn_iter_seek(txn_t *txn)
{
	txn_check_iter
	txn->iter = txn->j->db->db_api->iter_seek(txn->iter, &txn->key, 0);
	if (txn->iter == NULL) {
		txn->ret = KNOT_ENOENT;
	}
}

static void txn_iter_key(txn_t *txn, knot_db_val_t *at_key)
{
	txn_check_iter
	txn->ret = txn->j->db->db_api->iter_key(txn->iter, at_key);
}

static void txn_iter_val(txn_t *txn)
{
	txn_check_iter
	txn->ret = txn->j->db->db_api->iter_val(txn->iter, &txn->val);
}

static void txn_iter_next(txn_t *txn)
{
	txn_check_iter
	txn->iter = txn->j->db->db_api->iter_next(txn->iter);
	if (txn->iter == NULL) {
		txn->ret = KNOT_ENOENT;
	}
}

static void txn_iter_finish(txn_t *txn)
{
	if (txn->iter != NULL) {
		txn->j->db->db_api->iter_finish(txn->iter);
	}
	txn->iter = NULL;
}

static void txn_abort(txn_t *txn)
{
	if (txn->ret == KNOT_ESEMCHECK) {
		return;
	}
	txn_iter_finish(txn);
	txn->j->db->db_api->txn_abort(txn->txn);
	if (txn->ret == KNOT_EOK) {
		txn->ret = KNOT_ESEMCHECK;
	}
}

static void txn_commit(txn_t *txn)
{
	if (txn->is_rw) {
		txn_commit_md(first_serial);
		txn_commit_md(last_serial);
		txn_commit_md(last_serial_to);
		txn_commit_md(last_flushed);
		txn_commit_md(merged_serial);
		txn_commit_md(dirty_serial);
		txn_commit_md(changeset_count);
		txn_commit_md(flags);
	}

	if (txn->ret != KNOT_EOK) {
		txn_abort(txn);
		return;
	}

	txn_iter_finish(txn);
	txn->ret = txn->j->db->db_api->txn_commit(txn->txn);

	if (txn->ret == KNOT_EOK) {
		txn->ret = KNOT_ESEMCHECK;
	}
	txn_abort(txn); // no effect if all ok
}

static void txn_restart(txn_t *txn)
{
	txn_commit(txn);
	if (txn->ret == KNOT_ESEMCHECK) {
		txn_begin(txn, txn->is_rw);
	}
}

static void txn_reuse(txn_t **txn, txn_t *to_reuse, bool write_allowed)
{
	if (to_reuse == NULL) {
		txn_begin(*txn, write_allowed);
	}
	else {
		*txn = to_reuse;
	}
}

static void txn_unreuse(txn_t **txn, txn_t *reused)
{
	if (reused == NULL) {
		txn_commit(*txn);
	}
}

#define reuse_txn(name, journal, to_reuse, wa) local_txn_t(name, journal); txn_reuse(&name, to_reuse, wa)
#define unreuse_txn(name, reused) txn_unreuse(&name, reused)

/*
 * ***************************** PART II ******************************
 *
 *  DB metadata manip. and Chunk metadata headers
 *
 * ********************************************************************
 */

static void md_get(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint64_t *res)
{
	txn_check(txn);
	txn_key_str(txn, zone, mdkey);
	uint64_t res1 = 0;
	if (txn_find(txn)) {
		txn_val_u64(txn, &res1);
	}
	*res = res1;
}

static void md_get32(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint32_t *res)
{
	uint64_t res1 = 0;
	md_get(txn, zone, mdkey, &res1);
	if (res1 > UINT32_MAX) {
		txn->ret = KNOT_EMALF;
	} else {
		*res = (uint32_t)res1;
	}
}

// allocates res
static void md_get_common_last_inserter_zone(txn_t *txn, knot_dname_t **res)
{
	txn_check(txn);
	txn_key_str(txn, NULL, MDKEY_GLOBAL_LAST_INSERTER_ZONE);
	if (txn_find(txn)) {
		*res = knot_dname_copy(txn->val.data, NULL);
	}
	else {
		*res = NULL;
	}
}

static int md_set_common_last_inserter_zone(txn_t *txn, knot_dname_t *zone)
{
	txn_check_ret(txn);
	txn_key_str(txn, NULL, MDKEY_GLOBAL_LAST_INSERTER_ZONE);
	txn->val.len = knot_dname_size(zone);
	txn->val.data = zone;
	txn_insert(txn);
	return txn->ret;
}

static void md_del_last_inserter_zone(txn_t *txn, knot_dname_t *if_equals)
{
	txn_check(txn);
	txn_key_str(txn, NULL, MDKEY_GLOBAL_LAST_INSERTER_ZONE);
	if (txn_find(txn)) {
		if (if_equals == NULL || knot_dname_is_equal(txn->val.data, if_equals)) {
			txn_del(txn);
		}
	}
}

static void md_get_common_last_occupied(txn_t *txn, size_t *res)
{
	uint64_t sres = 0;
	md_get(txn, NULL, MDKEY_GLOBAL_LAST_TOTAL_OCCUPIED, &sres);
	*res = (size_t) sres;
}

static void md_set(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint64_t val)
{
	txn_key_str(txn, zone, mdkey);
	uint64_t val1 = htobe64(val);
	txn->val.len = sizeof(uint64_t);
	txn->val.data = &val1;
	txn_insert(txn);
}

static void md_set32(txn_t *txn, const knot_dname_t *zone, const char *mdkey, uint32_t val)
{
	txn_key_str(txn, zone, mdkey);
	uint32_t val1 = htobe32(val);
	txn->val.len = sizeof(uint32_t);
	txn->val.data = &val1;
	txn_insert(txn);
}

static bool md_flag(txn_t *txn, int flag)
{
	return (txn->shadow_md.flags & flag);
}

/*! \brief Marks metadata as flushed */
static void md_flush(txn_t *txn)
{
	if (md_flag(txn, SERIAL_TO_VALID)) {
		txn->shadow_md.last_flushed = txn->shadow_md.last_serial;
		txn->shadow_md.flags |= LAST_FLUSHED_VALID;
	}
}

static int md_flushed(txn_t *txn)
{
	return (!md_flag(txn, SERIAL_TO_VALID) ||
		(md_flag(txn, LAST_FLUSHED_VALID) &&
		 serial_compare(txn->shadow_md.last_flushed, txn->shadow_md.last_serial) == 0));
}

static void make_header(knot_db_val_t *to, uint32_t serial_to, int chunk_count)
{
	assert(to->len >= JOURNAL_HEADER_SIZE);
	assert(chunk_count > 0);

	uint32_t be_serial_to = htobe32(serial_to);
	uint32_t be_chunk_count = htobe32((uint32_t)chunk_count);

	memcpy(to->data, &be_serial_to, sizeof(be_serial_to));
	memcpy(to->data + sizeof(be_serial_to), &be_chunk_count, sizeof(be_chunk_count));
	memset(to->data + sizeof(be_serial_to) + sizeof(be_chunk_count), 0,
	       JOURNAL_HEADER_SIZE - sizeof(be_serial_to) - sizeof(be_chunk_count));
}

/*! \brief read properties from chunk header "from". All the output params are optional */
static void unmake_header(const knot_db_val_t *from, uint32_t *serial_to,
			  int *chunk_count, size_t *header_size)
{
	assert(from->len >= JOURNAL_HEADER_SIZE);

	uint32_t be_serial_to, be_chunk_count;
	if (serial_to != NULL) {
		memcpy(&be_serial_to, from->data, sizeof(be_serial_to));
		*serial_to = be32toh(be_serial_to);
	}
	if (chunk_count != NULL) {
		memcpy(&be_chunk_count, from->data + sizeof(be_serial_to), sizeof(be_chunk_count));
		assert(be32toh(be_chunk_count) <= INT_MAX);
		*chunk_count = (int)be32toh(be_chunk_count);
	}
	if (header_size != NULL) {
		*header_size = JOURNAL_HEADER_SIZE;
	}
}

static int first_digit(char * of)
{
	return atoi(of);
}

static void md_update_journal_count(txn_t * txn, int change_amount)
{
	uint64_t jcnt = 0;
	md_get(txn, NULL, MDKEY_GLOBAL_JOURNAL_COUNT, &jcnt);
	md_set(txn, NULL, MDKEY_GLOBAL_JOURNAL_COUNT, jcnt + change_amount);
}

static int initial_md_check(journal_t *j, bool *dirty_present)
{
	*dirty_present = 0;

	bool something_updated = false;

	local_txn_t(txn, j);
	txn_begin(txn, true);
	txn_key_str(txn, NULL, MDKEY_GLOBAL_VERSION);
	if (!txn_find(txn)) {
		txn->val.len = strlen(JOURNAL_VERSION) + 1;
		txn->val.data = JOURNAL_VERSION;
		txn_insert(txn);
		something_updated = true;
	}
	else {
		char * jver = txn->val.data;
		if (first_digit(jver) != first_digit(JOURNAL_VERSION)) {
			txn_abort(txn);
			return KNOT_ENOTSUP;
		}
	}
	txn_key_str(txn, j->zone, MDKEY_PERZONE_FLAGS);
	if (!txn_find(txn)) {
		md_update_journal_count(txn, +1);
		something_updated = true;
	}
	*dirty_present = md_flag(txn, DIRTY_SERIAL_VALID);

	if (something_updated) {
		txn_commit(txn);
	}
	else { // abort to gain up speed when opening a lot of zones
		txn_abort(txn);
	}

	txn_ret(txn);
}

/*
 * **************************** PART III ******************************
 *
 *  DB iteration
 *
 * ********************************************************************
 */

enum {
	JOURNAL_ITERATION_CHUNKS,     // call the iteration callback for each chunk read, with just the chunk in ctx->val
	JOURNAL_ITERATION_CHANGESETS  // call the iteration callback after the last chunk of a changeset read, with all its chunks in ctx->val
};

typedef struct {
	txn_t *txn;		// DB txn not to be touched by callback, just contains journal pointer
	uint32_t serial;	// serial-from of current changeset
	uint32_t serial_to;	// serial-to of current changeset
	const int method;	// JOURNAL_ITERATION_CHUNKS or JOURNAL_ITERATION_CHANGESETS, to be set by the caller of iterate()
	int chunk_index;	// index of current chunk
	int chunk_count;	// # of chunks of current changeset
	knot_db_val_t *val;	// one val if JOURNAL_ITERATION_CHUNKS; chunk_count vals if JOURNAL_ITERATION_CHANGESETS
	knot_db_iter_t *iter;	// DB iteration context, not to be touched by callback
	void *iter_context;	// anything to send to the callback by the caller of iterate(), untouched by iterate()
} iteration_ctx_t;

/*!
 * \brief Move iter to next changeset chunk.
 *
 * Try optimisticly fast move to next DB item. But the changeset can be out of order,
 * so if we don't succeed (different serial or end of DB), we lookup next serial slowly.
 */
static void get_iter_next(txn_t *txn, uint32_t expect_serial, int expect_chunk)
{
	knot_db_val_t other_key = { 0 };

	txn_check(txn);
	txn_iter_next(txn);
	txn_iter_key(txn, &other_key);
	txn_key_2u32(txn, txn->j->zone, expect_serial, (uint32_t)expect_chunk);
	if (txn->ret == KNOT_ENOENT ||
	    (txn->ret == KNOT_EOK && txn_cmpkey(txn, &other_key) != 0)) {
			txn_iter_seek(txn);
	}
}

typedef int (*iteration_cb_t)(iteration_ctx_t *ctx);

static int iterate(journal_t *j, txn_t *_txn, iteration_cb_t cb, int method,
                   void *iter_context, uint32_t first, uint32_t last)
{
	reuse_txn(txn, j, _txn, true);

	iteration_ctx_t ctx = {
		.method = method,
		.iter_context = iter_context,
		.txn = txn,
		.serial = first,
		.chunk_index = 0
	};

	knot_db_val_t *vals = NULL;

	txn_iter_begin(txn);

	txn_key_2u32(txn, j->zone, ctx.serial, ctx.chunk_index);
	txn_iter_seek(txn);

	ctx.val = &txn->val;

	while (true) {
		txn_iter_val(txn);
		if (txn->ret != KNOT_EOK) {
			break;
		}

		unmake_header(&txn->val, &ctx.serial_to, &ctx.chunk_count, NULL);

		if (method == JOURNAL_ITERATION_CHANGESETS) {
			if (ctx.chunk_index == 0) {
				if (vals != NULL) free(vals);
				vals = malloc(ctx.chunk_count * sizeof(knot_db_val_t));
				if (vals == NULL) {
					txn->ret = KNOT_ENOMEM;
					break;
				}
				ctx.val = vals;
			}
			memcpy(vals + ctx.chunk_index, &txn->val, sizeof(knot_db_val_t));
		}

		if (method == JOURNAL_ITERATION_CHUNKS) {
			txn->ret = cb(&ctx);
		}

		if (ctx.chunk_index == ctx.chunk_count - 1) { // hit last chunk of current changeset
			if (method == JOURNAL_ITERATION_CHANGESETS) {
				txn->ret = cb(&ctx);
			}

			if (ctx.serial == last) {
				break; // standard loop exit here
			}

			ctx.serial = ctx.serial_to;
			ctx.chunk_index = 0;
		}
		else {
			ctx.chunk_index++;
		}

		get_iter_next(txn, ctx.serial, ctx.chunk_index);
	}

	if (vals != NULL) {
		free(vals);
	}
	txn_iter_finish(txn);

	unreuse_txn(txn, _txn);

	txn_ret(txn);
}

/*
 * ***************************** PART IV ******************************
 *
 *  Reading changesets
 *
 * ********************************************************************
 */

/*! \brief Deserialize changeset from chunks (in vals) */
static int vals_to_changeset(knot_db_val_t *vals, int nvals,
                             const knot_dname_t *zone_name, changeset_t **ch)
{
	uint8_t *valps[nvals];
	size_t vallens[nvals];
	for (int i = 0; i < nvals; i++) {
		valps[i] = vals[i].data + JOURNAL_HEADER_SIZE;
		vallens[i] = vals[i].len - JOURNAL_HEADER_SIZE;
	}

	changeset_t *t_ch = changeset_new(zone_name);
	if (t_ch == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = changeset_deserialize(t_ch, valps, vallens, nvals);

	if (ret != KNOT_EOK) {
		changeset_free(t_ch);
		return ret;
	}
	*ch = t_ch;
	return KNOT_EOK;
}

static int load_one_itercb(iteration_ctx_t *ctx)
{
	changeset_t *ch = NULL, **targ = ctx->iter_context;
	if (*targ != NULL) {
		return KNOT_EINVAL;
	}

	int ret = vals_to_changeset(ctx->val, ctx->chunk_count, ctx->txn->j->zone, &ch);
	if (ret == KNOT_EOK) *targ = ch;
	return ret;
}

static int load_list_itercb(iteration_ctx_t *ctx)
{
	changeset_t *ch = NULL;
	list_t *chlist = *(list_t **) ctx->iter_context;

	int ret = vals_to_changeset(ctx->val, ctx->chunk_count, ctx->txn->j->zone, &ch);

	if (ret == KNOT_EOK) {
		add_tail(chlist, &ch->n);
	}
	return ret;
}

/*! \brief Load one changeset (with serial) from DB */
static int load_one(journal_t *j, txn_t *_txn, uint32_t serial, changeset_t **ch)
{
	reuse_txn(txn, j, _txn, false);
	changeset_t *rch = NULL;
	iterate(j, txn, load_one_itercb, JOURNAL_ITERATION_CHANGESETS, &rch, serial, serial);
	unreuse_txn(txn, _txn);
	if (txn_finished_ok(txn)) {
		if (rch == NULL) txn->ret = KNOT_ENOENT;
		else *ch = rch;
	}
	txn_ret(txn);
}

static int load_merged_changeset(journal_t *j, txn_t *_txn, changeset_t **mch,
                                 const uint32_t *only_if_serial)
{
	assert(*mch == NULL);

	reuse_txn(txn, j, _txn, false);
	txn_check_ret(txn);
	uint32_t ms = txn->shadow_md.merged_serial, fl = txn->shadow_md.flags;

	if ((fl & MERGED_SERIAL_VALID) &&
	    (only_if_serial == NULL || serial_compare(ms, *only_if_serial) == 0)) {
		load_one(j, txn, ms, mch);
	}
	unreuse_txn(txn, _txn);

	txn_ret(txn);
}

/*! \brief API: load all changesets since "from" serial into dst. */
int journal_load_changesets(journal_t *j, list_t *dst, uint32_t from)
{
	if (j == NULL || j->db == NULL || dst == NULL) return KNOT_EINVAL;

	local_txn_t(txn, j);
	txn_begin(txn, false);

	changeset_t *mch = NULL;
	load_merged_changeset(j, txn, &mch, &from);
	if (mch != NULL) {
		add_tail(dst, &mch->n);
		from = knot_soa_serial(&mch->soa_to->rrs);
	}

	uint32_t ls = txn->shadow_md.last_serial;
	iterate(j, txn, load_list_itercb, JOURNAL_ITERATION_CHANGESETS, &dst, from, ls);
	txn_commit(txn);

	txn_ret(txn);
}

/*
 * ***************************** PART V *******************************
 *
 *  Deleting changesets
 *
 * ********************************************************************
 */

typedef struct {
	size_t freed_approx;
	size_t to_be_freed;
} delete_status_t;

static int del_upto_itercb(iteration_ctx_t *ctx)
{
	txn_key_2u32(ctx->txn, ctx->txn->j->zone, ctx->serial, ctx->chunk_index);
	txn_del(ctx->txn);
	txn_check_ret(ctx->txn);

	// one whole changeset has been deleted => update metadata.
	// We are sure that the deleted changeset is first at this time.
	// If it's not merged changeset, point first_serial to next one
	if (ctx->chunk_index == ctx->chunk_count - 1) {
		if (!md_flag(ctx->txn, MERGED_SERIAL_VALID) ||
		    serial_compare(ctx->txn->shadow_md.merged_serial,ctx->serial) != 0) {
			ctx->txn->shadow_md.first_serial = ctx->serial_to;
			ctx->txn->shadow_md.changeset_count--;
		}
		if (serial_compare(ctx->txn->shadow_md.last_flushed, ctx->serial) == 0) {
			ctx->txn->shadow_md.flags &= ~LAST_FLUSHED_VALID;
		}
		if (serial_compare(ctx->txn->shadow_md.last_serial,  ctx->serial) == 0) {
			ctx->txn->shadow_md.flags &= ~SERIAL_TO_VALID;
		}
		if (serial_compare(ctx->txn->shadow_md.merged_serial,ctx->serial) == 0) {
			ctx->txn->shadow_md.flags &= ~MERGED_SERIAL_VALID;
		}
	}
	return KNOT_EOK;
}

/*! \brief Delete from beginning of DB up to "last" changeset including.
 * Please ensure (dbfirst == j->metadata.first_serial) */
static int delete_upto(journal_t *j, txn_t *txn, uint32_t dbfirst, uint32_t last)
{
	return iterate(j, txn, del_upto_itercb, JOURNAL_ITERATION_CHUNKS, NULL, dbfirst, last);
}

static int delete_merged_changeset(journal_t *j, txn_t *t)
{
	reuse_txn(txn, j, t, true);
	txn_check_ret(txn);
	if (!md_flag(txn, MERGED_SERIAL_VALID)) {
		txn->ret = KNOT_ENOENT;
	}
	else {
		delete_upto(j, txn, txn->shadow_md.merged_serial, txn->shadow_md.merged_serial);
	}
	unreuse_txn(txn, t);
	txn_ret(txn);
}

static int drop_journal(journal_t *j, txn_t *_txn)
{
	reuse_txn(txn, j, _txn, true);
	txn_check_ret(txn);
	if (md_flag(txn, MERGED_SERIAL_VALID)) {
		delete_merged_changeset(j, txn);
	}
	if (md_flag(txn, SERIAL_TO_VALID)) {
		delete_upto(j, txn, txn->shadow_md.first_serial, txn->shadow_md.last_serial);
	}
	md_del_last_inserter_zone(txn, j->zone);
	md_set(txn, j->zone, MDKEY_PERZONE_OCCUPIED, 0);
	unreuse_txn(txn, _txn);
	txn_ret(txn);
}

static int del_tofree_itercb(iteration_ctx_t *ctx)
{
	delete_status_t *ds = ctx->iter_context;

	if (ds->to_be_freed == 0) {
		return KNOT_EOK; // all done, just running through the rest of records w/o change
	}

	txn_key_2u32(ctx->txn, ctx->txn->j->zone, ctx->serial, ctx->chunk_index);
	txn_del(ctx->txn);
	txn_check_ret(ctx->txn);

	ds->freed_approx += /*4096 + */ctx->val->len;

	// when whole changeset deleted, check target and update metadata
	if (ctx->chunk_index == ctx->chunk_count - 1) {
		ctx->txn->shadow_md.first_serial = ctx->serial_to;
		ctx->txn->shadow_md.changeset_count--;
		if (serial_compare(ctx->txn->shadow_md.last_flushed, ctx->serial) == 0) {
			ctx->txn->shadow_md.flags &= ~LAST_FLUSHED_VALID;
			ds->to_be_freed = 0; // prevents deleting unflushed changesets
		}
		if (serial_compare(ctx->txn->shadow_md.last_serial, ctx->serial) == 0) {
			ctx->txn->shadow_md.flags &= ~SERIAL_TO_VALID;
		}
		if (ds->freed_approx >= ds->to_be_freed) {
			ds->to_be_freed = 0;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Deletes from j->db oldest changesets to free up space
 *
 * It tries deleting olny flushed changesets, preserves all unflushed ones.
 *
 * \retval KNOT_EOK if no error, even if too little or nothing deleted (check really_freed for result); KNOT_E* if error
 */
static int delete_tofree(journal_t *j, txn_t *_txn, size_t to_be_freed, size_t *really_freed)
{
	reuse_txn(txn, j, _txn, true);
	txn_check_ret(txn);

	if (!md_flag(txn, LAST_FLUSHED_VALID)) {
		*really_freed = 0;
		return KNOT_EOK;
	}
	delete_status_t ds = { .freed_approx = 0, .to_be_freed = to_be_freed };
	iterate(j, txn, del_tofree_itercb, JOURNAL_ITERATION_CHUNKS, &ds,
	        txn->shadow_md.first_serial, txn->shadow_md.last_serial);
	unreuse_txn(txn, _txn);

	if (txn_finished_ok(txn)) *really_freed = ds.freed_approx;
	txn_ret(txn);
}

static int del_count_itercb(iteration_ctx_t *ctx)
{
	delete_status_t *ds = ctx->iter_context;
	if (ds->freed_approx >= ds->to_be_freed) {
		return KNOT_EOK;
	}
	txn_key_2u32(ctx->txn, ctx->txn->j->zone, ctx->serial, ctx->chunk_index);
	txn_del(ctx->txn);
	txn_check_ret(ctx->txn);

	// when whole changeset deleted, check target and update metadata
	if (ctx->chunk_index == ctx->chunk_count - 1) {
		ctx->txn->shadow_md.first_serial = ctx->serial_to;
		ctx->txn->shadow_md.changeset_count--;
		if (serial_compare(ctx->txn->shadow_md.last_flushed, ctx->serial) == 0) {
			ctx->txn->shadow_md.flags &= ~LAST_FLUSHED_VALID;
			ds->to_be_freed = ds->freed_approx; // prevents deleting unflushed changesets
		}
		if (serial_compare(ctx->txn->shadow_md.last_serial, ctx->serial) == 0) {
			ctx->txn->shadow_md.flags &= ~SERIAL_TO_VALID;
		}
		ds->freed_approx++;
	}
	return KNOT_EOK;
}

/*!
 * \brief Deletes specified number of changesets
 *
 * It tries deleting olny flushed changesets, preserves all unflushed ones.
 *
 * \retval KNOT_EOK if no error, even if too little or nothing deleted (check really_deleted for result)
 * \return KNOT_E* if error
 */
static int delete_count(journal_t *j, txn_t *_txn, size_t to_be_deleted, size_t *really_deleted)
{
	reuse_txn(txn, j, _txn, true);
	txn_check_ret(txn);

	if (!md_flag(txn, LAST_FLUSHED_VALID)) {
		*really_deleted = 0;
		return KNOT_EOK;
	}
	delete_status_t ds = { .freed_approx = 0, .to_be_freed = to_be_deleted };
	iterate(j, txn, del_count_itercb, JOURNAL_ITERATION_CHUNKS, &ds,
	        txn->shadow_md.first_serial, txn->shadow_md.last_serial);
	unreuse_txn(txn, _txn);

	if (txn_finished_ok(txn)) *really_deleted = ds.freed_approx;
	txn_ret(txn);
}

static int delete_dirty_serial(journal_t *j, txn_t *_txn)
{
	reuse_txn(txn, j, _txn, true);
	txn_check_ret(txn);

	if (!md_flag(txn, DIRTY_SERIAL_VALID)) return KNOT_EOK;

	uint32_t ds = txn->shadow_md.dirty_serial, chunk = 0;

	txn_key_2u32(txn, j->zone, ds, chunk);
	while (txn_find(txn)) {
		txn_del(txn);
		txn_key_2u32(txn, j->zone, ds, ++chunk);
	}
	unreuse_txn(txn, _txn);
	if (txn_finished_ok(txn)) {
		txn->shadow_md.flags &= ~DIRTY_SERIAL_VALID;
	}
	txn_ret(txn);
}

/*
 * ***************************** PART VI ******************************
 *
 *  Writing changesets
 *
 * ********************************************************************
 */

static int merge_itercb(iteration_ctx_t *ctx)
{
	changeset_t *ch = NULL, *mch = *(changeset_t **)ctx->iter_context;

	int ret = vals_to_changeset(ctx->val, ctx->chunk_count, ctx->txn->j->zone, &ch);
	if (ret == KNOT_EOK) {
		ret = changeset_merge(mch, ch);
		changeset_free(ch);
	}
	return ret;
}

static int merge_unflushed_changesets(journal_t *j, txn_t *_txn, changeset_t **mch)
{
	reuse_txn(txn, j, _txn, false);
	txn_check_ret(txn);
	*mch = NULL;
	if (md_flushed(txn)) {
		goto m_u_ch_end;
	}
	bool was_merged = md_flag(txn, MERGED_SERIAL_VALID);
	bool was_flushed = md_flag(txn, LAST_FLUSHED_VALID);
	uint32_t from = was_merged ? txn->shadow_md.merged_serial :
	                             (was_flushed ? txn->shadow_md.last_flushed :
	                                            txn->shadow_md.first_serial);
	txn->ret = load_one(j, txn, from, mch);
	if (!was_merged && was_flushed && txn->ret == KNOT_EOK) {
		from = knot_soa_serial(&(*mch)->soa_to->rrs);
		changeset_free(*mch);
		*mch = NULL;
		txn->ret = load_one(j, txn, from, mch);
	}
	if (txn->ret != KNOT_EOK) {
		goto m_u_ch_end;
	}
	from = knot_soa_serial(&(*mch)->soa_to->rrs);

	txn->ret = iterate(j, txn, merge_itercb, JOURNAL_ITERATION_CHANGESETS,
	                   mch, from, txn->shadow_md.last_serial);

m_u_ch_end:
	unreuse_txn(txn, _txn);
	if (!txn_finished_ok(txn) && *mch != NULL) {
		changeset_free(*mch);
		*mch = NULL;
	}
	txn_ret(txn);
}

// uses local context, e.g.: j, txn, changesets, nchs, serialized_size_total, store_changeset_cleanup, inserting_merged
#define try_flush \
	if (!md_flushed(txn)) { \
		if (journal_merge_allowed(j)) { \
			changeset_t *merged; \
			merge_unflushed_changesets(j, txn, &merged); \
			add_tail(changesets, &merged->n); \
			nchs++; \
			serialized_size_total += changeset_serialized_size(merged); \
			md_flush(txn); \
			inserting_merged = true; \
		} \
		else { \
			txn->ret = KNOT_EBUSY; \
			goto store_changeset_cleanup; \
		} \
	}

static int store_changesets(journal_t *j, list_t *changesets)
{
	// PART 1 : initializers, compute serialized_sizes, transaction start
	changeset_t *ch;

	size_t nchs = 0, serialized_size_total = 0, inserted_size = 0, insert_txn_count = 1;

	uint8_t *allchunks = NULL;
	uint8_t **chunkptrs = NULL;
	size_t *chunksizes = NULL;
	knot_db_val_t *vals = NULL;

	int inserting_merged = false;

	WALK_LIST(ch, *changesets) {
		nchs++;
		serialized_size_total += changeset_serialized_size(ch);
	}

	local_txn_t(txn, j);
	txn_begin(txn, true);

	// if you're tempted to add dirty_serial deletion somewhere here, you're wrong. Don't do it.

	// PART 2 : recalculating the previous insert's occupy change
	size_t occupied_last, occupied_now;
	md_get_common_last_occupied(txn, &occupied_last);
	occupied_now = knot_db_lmdb_get_usage(j->db->db);
	md_set(txn, NULL, MDKEY_GLOBAL_LAST_TOTAL_OCCUPIED, occupied_now);
	if (occupied_now != occupied_last) {
		knot_dname_t *last_zone = NULL;
		uint64_t lz_occupied;
		md_get_common_last_inserter_zone(txn, &last_zone);
		if (last_zone != NULL) {
			md_get(txn, last_zone, MDKEY_PERZONE_OCCUPIED, &lz_occupied);
			lz_occupied = (lz_occupied + occupied_now > occupied_last ?
			               lz_occupied + occupied_now - occupied_last : 0);
			md_set(txn, last_zone, MDKEY_PERZONE_OCCUPIED, lz_occupied);
			free(last_zone);
		}
	}
	md_set_common_last_inserter_zone(txn, j->zone);

	// PART 3 : check if we exceeded designed occupation and delete some
	uint64_t occupied = 0, occupied_max;
	md_get(txn, j->zone, MDKEY_PERZONE_OCCUPIED, &occupied);
	occupied_max = journal_max_usage(j);
	occupied += serialized_size_total;
	if (occupied > occupied_max) {
		size_t freed;
		size_t tofree = (occupied - occupied_max) * journal_tofree_factor(j);
		size_t free_min = tofree * journal_minfree_factor(j);
		delete_tofree(j, txn, tofree, &freed);
		if (freed < free_min) {
			tofree -= freed;
			free_min -= freed;
			try_flush
			delete_tofree(j, txn, tofree, &freed);
			if (freed < free_min) {
				txn->ret = KNOT_ESPACE;
				log_zone_warning(j->zone, "journal: unable to make free space for insert");
				goto store_changeset_cleanup;
			}
		}
	}

	// PART 3.5 : check if we exceeded history depth
	long over_limit = (long)txn->shadow_md.changeset_count - journal_max_changesets(j) +
			  list_size(changesets) - (inserting_merged ? 1 : 0);
	if (over_limit > 0) {
		size_t deled;
		delete_count(j, txn, over_limit, &deled);
		over_limit -= deled;
		if (over_limit > 0) {
			try_flush
			delete_count(j, txn, over_limit, &deled);
			// ignore further errors here, the limit is not so important
		}
	}

	// PART 4: continuity and duplicity check
	changeset_t * chs_head = (HEAD(*changesets));
	uint32_t serial = knot_soa_serial(&chs_head->soa_from->rrs);
	if (md_flag(txn, SERIAL_TO_VALID) && serial_compare(txn->shadow_md.last_serial_to, serial) != 0) {
		log_zone_warning(j->zone, "discontinuity in chages history (%u -> %u), dropping older changesets",
		                 txn->shadow_md.last_serial_to, serial);
		try_flush
		drop_journal(j, txn);
		txn_restart(txn);
	}
	WALK_LIST(ch, *changesets) {
		uint32_t serial_to = knot_soa_serial(&ch->soa_to->rrs);
		if (inserting_merged && ch == TAIL(*changesets)) {
			continue;
		}
		txn_key_2u32(txn, j->zone, serial_to, 0);
		if (txn_find(txn)) {
			log_zone_warning(j->zone, "duplicite changeset serial (%u), dropping older changesets",
			                 serial_to);
			try_flush
			delete_upto(j, txn, txn->shadow_md.first_serial, serial_to);
			txn_restart(txn);
		}
	}

	// PART 5: serializing into chunks
	WALK_LIST(ch, *changesets) {
		if (txn->ret != KNOT_EOK) {
			break;
		}

		// Twice chsize seems like enough room to store all chunks together.
		size_t maxchunks = changeset_serialized_size(ch) * 2 / CHUNK_MAX + 1, chunks;
		allchunks = malloc(maxchunks * CHUNK_MAX);
		chunkptrs = malloc(maxchunks * sizeof(uint8_t *));
		chunksizes = malloc(maxchunks * sizeof(size_t));
		vals = malloc(maxchunks * sizeof(knot_db_val_t));
		if (allchunks == NULL || chunkptrs == NULL || chunksizes == NULL || vals == NULL) {
			txn->ret = KNOT_ENOMEM;
			break;
		}
		for (int i = 0; i < maxchunks; i++) {
			chunkptrs[i] = allchunks + i*CHUNK_MAX + JOURNAL_HEADER_SIZE;
		}
		txn->ret = changeset_serialize(ch, chunkptrs, CHUNK_MAX - JOURNAL_HEADER_SIZE,
		                               maxchunks, chunksizes, &chunks);
		if (txn->ret != KNOT_EOK) {
			break;
		}

		uint32_t serial = knot_soa_serial(&ch->soa_from->rrs);
		uint32_t serial_to = knot_soa_serial(&ch->soa_to->rrs);

		for (int i = 0; i < chunks; i++) {
			vals[i].data = allchunks + i*CHUNK_MAX;
			vals[i].len = JOURNAL_HEADER_SIZE + chunksizes[i];
			make_header(vals + i, serial_to, chunks);
		}

	// PART 6: inserting vals into db
		for (int i = 0; i < chunks; i++) {
			if (txn->ret != KNOT_EOK) break;
			txn_key_2u32(txn, j->zone, serial, i);
			txn->val = vals[i];
			txn_insert(txn);
			inserted_size += (vals+i)->len;
			if ((float)inserted_size > journal_max_txn(j) * (float)j->db->fslimit) { // insert txn too large
				inserted_size = 0;
				txn->shadow_md.dirty_serial = serial;
				txn->shadow_md.flags |= DIRTY_SERIAL_VALID;
				txn_restart(txn);
				insert_txn_count++;
				txn->shadow_md.flags &= ~DIRTY_SERIAL_VALID;
			}
		}

	// PART 7: metadata update
		if (txn->ret != KNOT_EOK) {
			break;
		}
		if (inserting_merged && ch == TAIL(*changesets)) {
			txn->shadow_md.flags |= MERGED_SERIAL_VALID;
			txn->shadow_md.merged_serial = serial;
		}
		else {
			if (!md_flag(txn, SERIAL_TO_VALID)) {
				txn->shadow_md.first_serial = serial;
			}
			txn->shadow_md.flags |= SERIAL_TO_VALID;
			txn->shadow_md.last_serial = serial;
			txn->shadow_md.last_serial_to = serial_to;
			txn->shadow_md.changeset_count++;
		}

		free(allchunks);
		free(chunkptrs);
		free(chunksizes);
		free(vals);
		allchunks = NULL;
		chunkptrs = NULL;
		chunksizes = NULL;
		vals = NULL;
	}

	// PART X : finalization and cleanup

store_changeset_cleanup:

	txn_commit(txn);

	if (txn->ret != KNOT_ESEMCHECK) {
		local_txn_t(ddtxn, j);
		txn_begin(ddtxn, true);
		if (md_flag(ddtxn, DIRTY_SERIAL_VALID)) {
			delete_dirty_serial(j, ddtxn);
		}
		txn_commit(ddtxn);
	}

	if (allchunks != NULL) free(allchunks);
	if (chunkptrs != NULL) free(chunkptrs);
	if (chunksizes != NULL) free(chunksizes);
	if (vals != NULL) free(vals);

	changeset_t *dbgchst = TAIL(*changesets);

	if (inserting_merged) {
		// free the merged changeset
		rem_node(&dbgchst->n);
		changeset_free(dbgchst);
	}

	txn_ret(txn);
}
#undef try_flush

int journal_store_changeset(journal_t *journal, changeset_t *ch)
{
	if (journal == NULL || journal->db == NULL || ch == NULL) return KNOT_EINVAL;

	changeset_t *ch_shallowcopy = malloc(sizeof(changeset_t));
	if (ch_shallowcopy == NULL) {
		return KNOT_ENOMEM;
	}
	memcpy(ch_shallowcopy, ch, sizeof(changeset_t)); // we need to copy the changeset_t sructure not to break ch->n

	list_t list;
	init_list(&list);
	add_tail(&list, &ch_shallowcopy->n);
	int ret = store_changesets(journal, &list);

	free(ch_shallowcopy);
	return ret;
}

int journal_store_changesets(journal_t *journal, list_t *src)
{
	if (journal == NULL || journal->db == NULL || src == NULL) return KNOT_EINVAL;
	return store_changesets(journal, src);
}

/*
 * **************************** PART VII ******************************
 *
 *  Journal initialization and global manipulation
 *
 * ********************************************************************
 */

journal_t *journal_new()
{
	journal_t *j = malloc(sizeof(*j));
	if (j != NULL) {
		memset(j, 0, sizeof(*j));
	}
	return j;
}

void journal_free(journal_t **j)
{
	if (j == NULL || *j == NULL) return;

	if ((*j)->zone != NULL) {
		free((knot_dname_t *)(*j)->zone);
	}
	free(*j);
	*j = NULL;
}

static int open_journal_db_unsafe(journal_db_t **db)
{
	if ((*db)->db != NULL) return KNOT_EOK;

	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.path = (*db)->path;
	opts.mapsize = (*db)->fslimit;
	opts.maxdbs = 1;
	opts.maxreaders = JOURNAL_MAX_READERS;
	opts.flags.env = ((*db)->mode == JOURNAL_MODE_ASYNC ?
	                  KNOT_DB_LMDB_WRITEMAP | KNOT_DB_LMDB_MAPASYNC : 0);

	int ret = (*db)->db_api->init(&(*db)->db, NULL, &opts);
	if (ret != KNOT_EOK) {
		(*db)->db = NULL;
		return ret;
	}

	size_t real_fslimit = knot_db_lmdb_get_mapsize((*db)->db);
	(*db)->fslimit = real_fslimit;

	return KNOT_EOK;
}

static int open_journal_db(journal_db_t **db)
{
	if (*db == NULL) return KNOT_EINVAL;
	pthread_mutex_lock(&(*db)->db_mutex);
	int ret = open_journal_db_unsafe(db);
	pthread_mutex_unlock(&(*db)->db_mutex);
	return ret;
}

/*! \brief Open/create the journal based on the filesystem path to LMDB directory */
int journal_open(journal_t *j, journal_db_t **db, const knot_dname_t *zone_name)
{
	int ret = KNOT_EOK;

	if (j == NULL || (*db) == NULL) return KNOT_EINVAL;
	if (j->db != NULL) {
		return KNOT_EOK;
	}

	// open shared journal DB if not already
	if ((*db)->db == NULL) {
		ret = open_journal_db(db);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}
	j->db = *db;

	j->zone = knot_dname_copy(zone_name, NULL);
	if (j->zone == NULL) {
		return KNOT_ENOMEM;
	}

	bool dirty_serial_valid;
	ret = initial_md_check(j, &dirty_serial_valid);

	if (ret == KNOT_EOK && dirty_serial_valid) {
		delete_dirty_serial(j, NULL);
	}

	return ret;
}

void journal_close(journal_t *j)
{
	j->db = NULL;
	free(j->zone);
	j->zone = NULL;
}

int journal_db_init(journal_db_t **db, const char *lmdb_dir_path, size_t lmdb_fslimit,
                    journal_mode_t mode)
{
	if (*db != NULL) {
		return KNOT_EOK;
	}
	*db = malloc(sizeof(journal_db_t));
	if (*db == NULL) {
		return KNOT_ENOMEM;
	}
	journal_db_t dbinit = {
		.db = NULL,
		.db_api = knot_db_lmdb_api(),
		.path = strdup(lmdb_dir_path),
		.fslimit = ((lmdb_fslimit < JOURNAL_MIN_FSLIMIT) ? JOURNAL_MIN_FSLIMIT : lmdb_fslimit),
		.mode = mode,
	};
	memcpy(*db, &dbinit, sizeof(journal_db_t));
	pthread_mutex_init(&(*db)->db_mutex, NULL);
	return KNOT_EOK;
}

static void destroy_journal_db(journal_db_t **db)
{
	assert((*db)->db == NULL);

	pthread_mutex_destroy(&(*db)->db_mutex);
	free((*db)->path);
	free((*db));
	*db = NULL;
}

void journal_db_close(journal_db_t **db)
{
	if (db == NULL || *db == NULL) {
		return;
	}

	pthread_mutex_lock(&(*db)->db_mutex);
	if ((*db)->db != NULL) {
		(*db)->db_api->deinit((*db)->db);
		(*db)->db = NULL;
	}
	pthread_mutex_unlock(&(*db)->db_mutex);

	destroy_journal_db(db);
}

int journal_flush(journal_t *journal)
{
	if (journal == NULL || journal->db == NULL) {
		return KNOT_EINVAL;
	}

	local_txn_t(txn, journal);
	txn_begin(txn, true);
	md_flush(txn);
	txn_commit(txn);
	txn_ret(txn);
}

bool journal_exists(journal_db_t **db, knot_dname_t *zone_name)
{
	if (db == NULL || *db == NULL || zone_name == NULL) {
		return false;
	}

	if ((*db)->db == NULL) {
		struct stat st;
		if (stat((*db)->path, &st) != 0 || st.st_size == 0) {
			return false;
		}
		int ret = open_journal_db(db);
		if (ret != KNOT_EOK) {
			return false;
		}
	}

	journal_t fake_journal = { .db = *db, .zone = zone_name };
	local_txn_t(txn, &fake_journal);
	txn_begin(txn, false);
	txn_key_str(txn, zone_name, MDKEY_PERZONE_FLAGS);
	int res = txn_find(txn);
	txn_abort(txn);

	return (res == 1);
}

static knot_db_val_t *dbval_copy(const knot_db_val_t *from)
{
	knot_db_val_t *to = malloc(sizeof(knot_db_val_t) + from->len);
	if (to != NULL) {
		memcpy(to, from, sizeof(knot_db_val_t));
		to->data = to + 1; // == ((uit8_t *)to) + sizeof(knot_db_val_t)
		memcpy(to->data, from->data, from->len);
	}
	return to;
} // TODO think of moving this fun into different place/lib

int scrape_journal(journal_t *j)
{
	if (j->db == NULL) return KNOT_EINVAL;
	local_txn_t(txn, j);
	txn_begin(txn, true);
	txn_check_ret(txn);

	knot_db_val_t key = { .len = 0, .data = "" };

	list_t to_del;
	init_list(&to_del);

	txn_iter_begin(txn);
	while (txn->ret == KNOT_EOK && txn->iter != NULL) {
		txn_iter_key(txn, &key);
		if (knot_dname_is_equal((const knot_dname_t *) key.data, j->zone)) {
			knot_db_val_t * inskey = dbval_copy(&key);
			if (inskey == NULL) {
				txn->ret = KNOT_ENOMEM;
				goto scrape_end;
			}
			ptrlist_add(&to_del, inskey, NULL);
		}
		txn_iter_next(txn);
	}
	if (txn->ret == KNOT_ENOENT) {
		txn->ret = KNOT_EOK;
	}
	txn_iter_finish(txn);

	ptrnode_t *del_one;
	if (txn->ret == KNOT_EOK) {
		WALK_LIST(del_one, to_del) {
			txn->ret = j->db->db_api->del(txn->txn, (knot_db_val_t *)del_one->d);
		}
		md_update_journal_count(txn, -1);

		md_del_last_inserter_zone(txn, j->zone);

		txn->ret = j->db->db_api->txn_commit(txn->txn);
	}
scrape_end:

	WALK_LIST(del_one, to_del) {
		free(del_one->d);
	}

	ptrlist_free(&to_del, NULL);

	return txn->ret;
}

void journal_metadata_info(journal_t *j, bool *is_empty, uint32_t *serial_from, uint32_t *serial_to)
{
	// NOTE: there is NEVER the situation that only merged changeset would be present and no common changeset in db.

	if (j == NULL || j->db == NULL) {
		*is_empty = true;
		return;
	}

	local_txn_t(txn, j);
	txn_begin(txn, false);
	txn_check(txn);

	*is_empty = !md_flag(txn, SERIAL_TO_VALID);
	*serial_from = txn->shadow_md.first_serial;
	*serial_to = txn->shadow_md.last_serial_to;

	if (md_flag(txn, MERGED_SERIAL_VALID)) {
		*serial_from = txn->shadow_md.merged_serial;
	}
	txn_abort(txn);
}

int journal_db_list_zones(journal_db_t **db, list_t *zones)
{
	uint64_t expected_count;

	if (list_size(zones) > 0) {
		return KNOT_EINVAL;
	}

	if ((*db)->db == NULL) {
		int ret = open_journal_db(db);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	journal_t fake_journal = { .db = *db, .zone = (knot_dname_t *)"" };
	local_txn_t(txn, &fake_journal);
	txn_begin(txn, false);
	md_get(txn, NULL, MDKEY_GLOBAL_JOURNAL_COUNT, &expected_count);
	txn_check_ret(txn);

	knot_db_val_t key;
	txn_iter_begin(txn);
	while (txn->ret == KNOT_EOK && txn->iter != NULL) {
		txn_iter_key(txn, &key);

		int metaflag_len = strlen(MDKEY_PERZONE_FLAGS);
		char *compare_metaflag = key.data;
		compare_metaflag += key.len - 1;
		if (txn->ret == KNOT_EOK && *compare_metaflag == '\0') {
			compare_metaflag -= metaflag_len;
			if (strcmp(compare_metaflag, MDKEY_PERZONE_FLAGS) == 0) {
				char *found_zone = knot_dname_to_str_alloc((const knot_dname_t *)key.data);
				ptrlist_add(zones, found_zone, NULL);
			}
		}
		txn_iter_next(txn);
	}
	if (txn->ret == KNOT_ENOENT) {
		txn->ret = KNOT_EOK;
	}
	txn_iter_finish(txn);
	txn_abort(txn);
	if (list_size(zones) < 1) {
		txn->ret = KNOT_ENOENT;
	}
	if (list_size(zones) != expected_count) {
		txn->ret = KNOT_EMALF;
	}
	txn_ret(txn);
}

/*
 * *************************** PART VIII ******************************
 *
 *  Journal check
 *
 * ********************************************************************
 */

static void _jch_print(const knot_dname_t *zname, int warn_level, const char *format, ...)
{
	static char buf[512];
	strcpy(buf, "journal check: ");

	va_list args;
	va_start(args, format);
	vsprintf(buf + strlen(buf), format, args);
	va_end(args);

	switch (warn_level) {
	case JOURNAL_CHECK_INFO:
		log_zone_info(zname, "%s", buf);
		break;
	case JOURNAL_CHECK_WARN:
		log_zone_error(zname, "%s", buf);
		break;
	default:
		break;
	}
}

#define jch_print(wl, fmt_args...) if ((wl) <= warn_level) _jch_print(j->zone, wl, fmt_args)
#define jch_info(fmt_args...) jch_print(JOURNAL_CHECK_INFO, fmt_args)
#define jch_warn(fmt_args...) jch_print((allok = 0, JOURNAL_CHECK_WARN), fmt_args)
#define jch_txn(comment, fatal) do { if (txn->ret != KNOT_EOK && txn->ret != KNOT_ESEMCHECK) { \
                                     jch_warn("failed transaction: %s (%s)", (comment), knot_strerror(txn->ret)); \
                                     if (fatal) return txn->ret; } } while (0)

int journal_check(journal_t *j, journal_check_level_t warn_level)
{
	int ret, allok = 1;
	changeset_t *ch = NULL;
	uint32_t sfrom, sto;
	uint32_t first_unflushed;
	uint32_t chcount;

	jch_info("started");

	if (j->db == NULL) {
		jch_warn("is not open");
		return KNOT_ESEMCHECK;
	}

	local_txn_t(txn, j);
	txn_begin(txn, true);
	jch_txn("begin", true);

	jch_info("metadata: flags >> %d << fs %u ls %u lst %u lf %u ms %u ds %u cnt %u",
	         txn->shadow_md.flags, txn->shadow_md.first_serial, txn->shadow_md.last_serial,
	         txn->shadow_md.last_serial_to, txn->shadow_md.last_flushed, txn->shadow_md.merged_serial,
	         txn->shadow_md.dirty_serial, txn->shadow_md.changeset_count);

	chcount = txn->shadow_md.changeset_count;
	first_unflushed = txn->shadow_md.first_serial;

	if (md_flag(txn, DIRTY_SERIAL_VALID)) {
		jch_warn("there is some post-crash mess in the DB");
	}

	if (!md_flag(txn, SERIAL_TO_VALID)) {
		if (md_flag(txn, LAST_FLUSHED_VALID)) {
			jch_warn("journal flagged empty but last_flushed valid");
		}
		if (md_flag(txn, MERGED_SERIAL_VALID)) {
			jch_warn("no other than merged changeset present, this should not happen");
		}
		goto check_merged;
	}

	ret = load_one(j, txn, txn->shadow_md.first_serial, &ch);
	if (ret != KNOT_EOK) {
		jch_warn("can't read first changeset %u (%s)",
		         txn->shadow_md.first_serial, knot_strerror(ret));
		goto check_merged;
	}

	sfrom = knot_soa_serial(&ch->soa_from->rrs), sto = knot_soa_serial(&ch->soa_to->rrs);
	if (serial_compare(txn->shadow_md.first_serial, sfrom) != 0) {
		jch_warn("first changeset's serial 'from' %u is not ok", sfrom);
	}

	if (md_flag(txn, LAST_FLUSHED_VALID)) {
		changeset_free(ch);
		ret = load_one(j, txn, txn->shadow_md.last_flushed, &ch);
		if (ret != KNOT_EOK) {
			jch_warn("can't read last flushed changeset %u (%s)",
			         txn->shadow_md.last_flushed, knot_strerror(ret));
		}
		else {
			first_unflushed = knot_soa_serial(&ch->soa_to->rrs);
		}
	}
	if (ret == KNOT_EOK) {
		changeset_free(ch);
	}

	if (serial_compare(txn->shadow_md.last_serial_to, sto) == 0) {
		jch_info("there is just one changeset in the journal");
		goto check_merged;
	}
	ret = load_one(j, txn, sto, &ch);
	if (ret != KNOT_EOK) {
		jch_warn("can't read second changeset %u (%s)", sto, knot_strerror(ret));
	}
	else {
		sfrom = knot_soa_serial(&ch->soa_from->rrs);
		if (serial_compare(sfrom, sto) != 0) {
			jch_warn("second changeset's serial 'from' %u is not ok", sfrom);
		}
		changeset_free(ch);
	}

	sfrom = txn->shadow_md.first_serial;
	sto = txn->shadow_md.last_serial_to;
	txn_commit(txn);
	jch_txn("commit", true);

	list_t l;
	init_list(&l);
	ret = journal_load_changesets(j, &l, sfrom);
	if (ret != KNOT_EOK) {
		jch_warn("can't read all changesets %u -> %u (%s)", sfrom, sto, knot_strerror(ret));
		goto check_merged;
	}
	jch_info("listed %zu changesets", list_size(&l));
	if (list_size(&l) != chcount) {
		jch_warn("expected %u changesets but found %zu", chcount, list_size(&l));
	}

	ch = HEAD(l);
	if (serial_compare(sfrom, knot_soa_serial(&ch->soa_from->rrs)) != 0) {
		jch_warn("first listed changeset's serial 'from' %u is not ok",
		         knot_soa_serial(&ch->soa_from->rrs));
	}
	ch = TAIL(l);
	if (serial_compare(sto, knot_soa_serial(&ch->soa_to->rrs)) != 0) {
		jch_warn("last listed changeset's serial 'to' %u is not ok",
		         knot_soa_serial(&ch->soa_to->rrs));
	}
	changesets_free(&l);

check_merged:
	if (txn->ret != KNOT_ESEMCHECK) txn_abort(txn);
	txn_begin(txn, false);
	jch_txn("begin2", true);
	if (md_flag(txn, MERGED_SERIAL_VALID)) {
		ch = NULL;
		ret = load_merged_changeset(j, txn, &ch, NULL);
		if (ret != KNOT_EOK) {
			jch_warn("can't read merged changeset (%s)", knot_strerror(ret));
		}
		else {
			sfrom = knot_soa_serial(&ch->soa_from->rrs);
			sto = knot_soa_serial(&ch->soa_to->rrs);
			jch_info("merged changeset %u -> %u (size %zu)", sfrom, sto,
			         changeset_serialized_size(ch));
			if (serial_compare(sfrom, txn->shadow_md.merged_serial) != 0) {
				jch_warn("merged changeset's serial 'from' is not ok");
			}
			if (serial_compare(sto, first_unflushed) != 0) {
				jch_warn("merged changeset's serial 'to' is not ok");
			}
			changeset_free(ch);
		}
	}
	txn_commit(txn);
	jch_txn("commit2", true);

	if (allok) {
		jch_info("passed without errors");
	}

	return (allok ? KNOT_EOK : KNOT_ERROR);
}
