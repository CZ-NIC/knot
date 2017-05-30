/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/timers.h"

#include "contrib/wire_ctx.h"
#include "libknot/db/db.h"
#include "libknot/db/db_lmdb.h"

/*
 * # Timer database
 *
 * Timer database stores timestaps of events which need to be retained
 * accross server restarts. The key in the database is the zone name in
 * wire format. The value contains serialized timers.
 *
 * # Serialization format
 *
 * The value is a sequence of timers. Each timer consists of the timer
 * identifier (1 byte, unsigned integer) and timer value (8 bytes, unsigned
 * integer, network order).
 *
 * For example, the following byte sequence:
 *
 *     81 00 00 00 00 57 e3 e8 0a 82 00 00 00 00 57 e3 e9 a1
 *
 * Encodes the following timers:
 *
 *     last_flush = 1474553866
 *     last_refresh = 1474554273
 */

/**
 * \brief Timer database fields identifiers.
 *
 * Valid ID starts with '1' in MSB to avoid conflicts with "old timers".
 */
enum timer_id {
	TIMER_INVALID = 0,
	TIMER_SOA_EXPIRE = 0x80,
	TIMER_LAST_FLUSH,
	TIMER_LAST_REFRESH,
	TIMER_NEXT_REFRESH
};

#define TIMER_COUNT 4
#define TIMER_SIZE (sizeof(uint8_t) + sizeof(uint64_t))
#define SERIALIZED_SIZE (TIMER_COUNT * TIMER_SIZE)

/*!
 * \brief Serialize timers into a binary buffer.
 */
static int serialize_timers(const zone_timers_t *timers, uint8_t *data, size_t size)
{
	if (!timers || !data || size != SERIALIZED_SIZE) {
		return KNOT_EINVAL;
	}

	wire_ctx_t wire = wire_ctx_init(data, size);

	wire_ctx_write_u8(&wire, TIMER_SOA_EXPIRE);
	wire_ctx_write_u64(&wire, timers->soa_expire);
	wire_ctx_write_u8(&wire, TIMER_LAST_FLUSH);
	wire_ctx_write_u64(&wire, timers->last_flush);
	wire_ctx_write_u8(&wire, TIMER_LAST_REFRESH);
	wire_ctx_write_u64(&wire, timers->last_refresh);
	wire_ctx_write_u8(&wire, TIMER_NEXT_REFRESH);
	wire_ctx_write_u64(&wire, timers->next_refresh);

	assert(wire.error == KNOT_EOK);
	assert(wire_ctx_available(&wire) == 0);

	return KNOT_EOK;
}

/*!
 * \brief Deserialize timers from a binary buffer.
 *
 * \note Unkown timers are ignored.
 */
static int deserialize_timers(zone_timers_t *timers_ptr,
                              const uint8_t *data, size_t size)
{
	if (!timers_ptr || !data) {
		return KNOT_EINVAL;
	}

	zone_timers_t timers = { 0 };

	wire_ctx_t wire = wire_ctx_init_const(data, size);
	while (wire_ctx_available(&wire) >= TIMER_SIZE) {
		uint8_t id = wire_ctx_read_u8(&wire);
		uint64_t value = wire_ctx_read_u64(&wire);
		switch (id) {
		case TIMER_SOA_EXPIRE:   timers.soa_expire = value; break;
		case TIMER_LAST_FLUSH:   timers.last_flush = value; break;
		case TIMER_LAST_REFRESH: timers.last_refresh = value; break;
		case TIMER_NEXT_REFRESH: timers.next_refresh = value; break;
		default:                 break; // ignore
		}
	}

	if (wire_ctx_available(&wire) != 0) {
		return KNOT_EMALF;
	}

	assert(wire.error == KNOT_EOK);

	*timers_ptr = timers;
	return KNOT_EOK;
}

static int txn_write_timers(knot_db_txn_t *txn, const knot_dname_t *zone,
                            const zone_timers_t *timers)
{
	uint8_t data[SERIALIZED_SIZE] = { 0 };
	int ret = serialize_timers(timers, data, sizeof(data));
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_db_val_t key = { (uint8_t *)zone, knot_dname_size(zone) };
	knot_db_val_t val = { data, sizeof(data) };

	return knot_db_lmdb_api()->insert(txn, &key, &val, 0);
}

static int txn_read_timers(knot_db_txn_t *txn, const knot_dname_t *zone,
                           zone_timers_t *timers)
{
	knot_db_val_t key = { (uint8_t *)zone, knot_dname_size(zone) };
	knot_db_val_t val = { 0 };
	int ret = knot_db_lmdb_api()->find(txn, &key, &val, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return deserialize_timers(timers, val.data, val.len);
}

int zone_timers_open(const char *path, knot_db_t **db, size_t mapsize)
{
	if (path == NULL || db == NULL) {
		return KNOT_EINVAL;
	}

	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.mapsize = mapsize;
	opts.path = path;

	return knot_db_lmdb_api()->init(db, NULL, &opts);
}

void zone_timers_close(knot_db_t *db)
{
	if (db == NULL) {
		return;
	}

	knot_db_lmdb_api()->deinit(db);
}

int zone_timers_read(knot_db_t *db, const knot_dname_t *zone,
                     zone_timers_t *timers)
{
	if (!db || !zone || !timers) {
		return KNOT_EINVAL;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	knot_db_txn_t txn = { 0 };
	int ret = db_api->txn_begin(db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = txn_read_timers(&txn, zone, timers);
	db_api->txn_abort(&txn);

	return ret;
}

int zone_timers_write_begin(knot_db_t *db, knot_db_txn_t *txn)
{
	memset(txn, 0, sizeof(*txn));
	return knot_db_lmdb_api()->txn_begin(db, txn, KNOT_DB_SORTED);
}

int zone_timers_write_end(knot_db_txn_t *txn)
{
	return knot_db_lmdb_api()->txn_commit(txn);
}

int zone_timers_write(knot_db_t *db, const knot_dname_t *zone,
                      const zone_timers_t *timers, knot_db_txn_t *txn)
{
	if (!zone || !timers || (!db && !txn)) {
		return KNOT_EINVAL;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	knot_db_txn_t static_txn, *mytxn = txn;
	if (txn == NULL) {
		mytxn = &static_txn;
		int ret = db_api->txn_begin(db, mytxn, KNOT_DB_SORTED);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	int ret = txn_write_timers(mytxn, zone, timers);
	if (ret != KNOT_EOK) {
		db_api->txn_abort(mytxn);
		return ret;
	}

	if (txn == NULL) {
		db_api->txn_commit(mytxn);
	}

	return KNOT_EOK;
}

int zone_timers_sweep(knot_db_t *db, sweep_cb keep_zone, void *cb_data)
{
	if (!db || !keep_zone) {
		return KNOT_EINVAL;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	knot_db_txn_t txn = { 0 };
	int ret = db_api->txn_begin(db, &txn, KNOT_DB_SORTED);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_db_iter_t *it = NULL;
	for (it = db_api->iter_begin(&txn, 0); it != NULL; it = db_api->iter_next(it)) {
		knot_db_val_t key = { 0 };
		ret = db_api->iter_key(it, &key);
		if (ret != KNOT_EOK) {
			break;
		}

		const knot_dname_t *zone = (const knot_dname_t *)key.data;
		if (!keep_zone(zone, cb_data)) {
			ret = db_api->del(&txn, &key);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}
	db_api->iter_finish(it);

	if (ret != KNOT_EOK) {
		db_api->txn_abort(&txn);
		return ret;
	}

	return db_api->txn_commit(&txn);
}
