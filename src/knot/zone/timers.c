/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "knot/zone/timers.h"

#include "contrib/wire_ctx.h"
#include "knot/zone/zonedb.h"

/*
 * # Timer database
 *
 * Timer database stores timestamps of events which need to be retained
 * across server restarts. The key in the database is the zone name in
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

/*!
 * \brief Timer database fields identifiers.
 *
 * Valid ID starts with '1' in MSB to avoid conflicts with "old timers".
 */
enum timer_id {
	TIMER_INVALID        = 0,
	TIMER_SOA_EXPIRE     = 0x80, // DEPRECATED
	TIMER_LAST_FLUSH     = 0x81,
	TIMER_LAST_REFRESH   = 0x82, // DEPRECATED
	TIMER_NEXT_REFRESH   = 0x83,
	TIMER_NEXT_DS_CHECK  = 0x85,
	TIMER_NEXT_DS_PUSH   = 0x86,
	TIMER_CATALOG_MEMBER = 0x87,
	TIMER_LAST_NOTIFIED  = 0x88,
	TIMER_LAST_REFR_OK   = 0x89,
	TIMER_NEXT_EXPIRE    = 0x8a,
};

#define TIMER_SIZE (sizeof(uint8_t) + sizeof(uint64_t))

/*!
 * \brief Deserialize timers from a binary buffer.
 *
 * \note Unknown timers are ignored.
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
		case TIMER_SOA_EXPIRE:     timers.soa_expire = value; break;
		case TIMER_LAST_FLUSH:     timers.last_flush = value; break;
		case TIMER_LAST_REFRESH:   timers.last_refresh = value; break;
		case TIMER_NEXT_REFRESH:   timers.next_refresh = value; break;
		case TIMER_LAST_REFR_OK:   timers.last_refresh_ok = value; break;
		case TIMER_LAST_NOTIFIED:  timers.last_notified_serial = value; break;
		case TIMER_NEXT_DS_CHECK:  timers.next_ds_check = value; break;
		case TIMER_NEXT_DS_PUSH:   timers.next_ds_push = value; break;
		case TIMER_CATALOG_MEMBER: timers.catalog_member = value; break;
		case TIMER_NEXT_EXPIRE:    timers.next_expire = value; break;
		default:                   break; // ignore
		}
	}

	if (wire_ctx_available(&wire) != 0) {
		return KNOT_EMALF;
	}

	assert(wire.error == KNOT_EOK);

	*timers_ptr = timers;
	return KNOT_EOK;
}

static void txn_write_timers(knot_lmdb_txn_t *txn, const knot_dname_t *zone,
                             const zone_timers_t *timers)
{
	MDB_val k = { knot_dname_size(zone), (void *)zone };
	MDB_val v = knot_lmdb_make_key("BLBLBLBLBLBLBLBL",
		TIMER_LAST_FLUSH,    (uint64_t)timers->last_flush,
		TIMER_NEXT_REFRESH,  (uint64_t)timers->next_refresh,
		TIMER_LAST_REFR_OK,  (uint64_t)timers->last_refresh_ok,
		TIMER_LAST_NOTIFIED, timers->last_notified_serial,
		TIMER_NEXT_DS_CHECK, (uint64_t)timers->next_ds_check,
		TIMER_NEXT_DS_PUSH,  (uint64_t)timers->next_ds_push,
		TIMER_CATALOG_MEMBER,(uint64_t)timers->catalog_member,
		TIMER_NEXT_EXPIRE,   (uint64_t)timers->next_expire);
	knot_lmdb_insert(txn, &k, &v);
	free(v.mv_data);
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

int zone_timers_read(knot_lmdb_db_t *db, const knot_dname_t *zone,
                     zone_timers_t *timers)
{
	if (knot_lmdb_exists(db) == KNOT_ENODB) {
		return KNOT_ENODB;
	}
	int ret = knot_lmdb_open(db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, false);
	MDB_val k = { knot_dname_size(zone), (void *)zone };
	if (knot_lmdb_find(&txn, &k, KNOT_LMDB_EXACT | KNOT_LMDB_FORCE)) {
		deserialize_timers(timers, txn.cur_val.mv_data, txn.cur_val.mv_size);
	}
	knot_lmdb_abort(&txn);

	// backward compatibility
	// For catalog zones, next_expire is cleaned up later by zone_timers_sanitize().
	if (timers->next_expire == 0 && timers->last_refresh > 0) {
		timers->next_expire = timers->last_refresh + timers->soa_expire;
	}

	return txn.ret;
}

int zone_timers_write(knot_lmdb_db_t *db, const knot_dname_t *zone,
                      const zone_timers_t *timers)
{
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	txn_write_timers(&txn, zone, timers);
	knot_lmdb_commit(&txn);
	return txn.ret;
}

static void txn_zone_write(zone_t *z, knot_lmdb_txn_t *txn)
{
	txn_write_timers(txn, z->name, &z->timers);
}

int zone_timers_write_all(knot_lmdb_db_t *db, knot_zonedb_t *zonedb)
{
	int ret = knot_lmdb_open(db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	knot_zonedb_foreach(zonedb, txn_zone_write, &txn);
	knot_lmdb_commit(&txn);
	return txn.ret;
}

int zone_timers_sweep(knot_lmdb_db_t *db, sweep_cb keep_zone, void *cb_data)
{
	if (knot_lmdb_exists(db) == KNOT_ENODB) {
		return KNOT_EOK;
	}
	int ret = knot_lmdb_open(db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	knot_lmdb_forwhole(&txn) {
		if (!keep_zone((const knot_dname_t *)txn.cur_key.mv_data, cb_data)) {
			knot_lmdb_del_cur(&txn);
		}
	}
	knot_lmdb_commit(&txn);
	return txn.ret;
}

bool zone_timers_serial_notified(const zone_timers_t *timers, uint32_t serial)
{
	return (timers->last_notified_serial & LAST_NOTIFIED_SERIAL_VALID) &&
	       ((uint32_t)timers->last_notified_serial == serial);
}
