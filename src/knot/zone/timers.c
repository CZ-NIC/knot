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

#include "libknot/libknot.h"
#include "knot/zone/timers.h"
#include "contrib/wire.h"
#include "contrib/wire_ctx.h"

#define PERSISTENT_EVENT_COUNT 3

enum {
	KEY_REFRESH = 1,
	KEY_EXPIRE,
	KEY_FLUSH
};

// Do not change these mappings if you want backwards compatibility.
static const uint8_t event_id_to_key[ZONE_EVENT_COUNT] = {
	[ZONE_EVENT_REFRESH] = KEY_REFRESH,
	[ZONE_EVENT_EXPIRE] = KEY_EXPIRE,
	[ZONE_EVENT_FLUSH] = KEY_FLUSH
};

static const int key_to_event_id[PERSISTENT_EVENT_COUNT + 1] = {
	[KEY_REFRESH] = ZONE_EVENT_REFRESH,
	[KEY_EXPIRE] = ZONE_EVENT_EXPIRE,
	[KEY_FLUSH] = ZONE_EVENT_FLUSH
};

static bool known_event_key(uint8_t key)
{
	return key <= KEY_FLUSH;
}

#define EVENT_KEY_PAIR_SIZE (sizeof(uint8_t) + sizeof(int64_t))

static bool event_persistent(size_t event)
{
	return event_id_to_key[event] != 0;
}

/*! \brief Clear array of timers. */
static void clear_timers(time_t *timers)
{
	memset(timers, 0, ZONE_EVENT_COUNT * sizeof(time_t));
}

/*! \brief Stores timers for persistent events. */
static int store_timers(zone_t *zone, knot_db_txn_t *txn)
{
	// Create key
	knot_db_val_t key = { .len = knot_dname_size(zone->name), .data = zone->name };

	// Create value
	uint8_t packed_timer[EVENT_KEY_PAIR_SIZE * PERSISTENT_EVENT_COUNT];

	wire_ctx_t w = wire_ctx_init(packed_timer, sizeof(packed_timer));

	for (zone_event_type_t event = 0; event < ZONE_EVENT_COUNT; ++event) {
		if (!event_persistent(event)) {
			continue;
		}

		// Key
		wire_ctx_write_u8(&w, event_id_to_key[event]);

		// Value
		time_t value = zone_events_get_time(zone, event);
		if (event == ZONE_EVENT_EXPIRE && zone->flags & ZONE_EXPIRED) {
			/*
			 * WORKAROUND. The current timer database contains
			 * time stamps for running timers. The expiration
			 * in past indicates that the zone expired. We need
			 * to preserve this status across server restarts.
			 */
			value = 1;
		}
		wire_ctx_write_u64(&w, value);
	}

	if (w.error != KNOT_EOK) {
		return w.error;
	}

	knot_db_val_t val = { .len = sizeof(packed_timer), .data = packed_timer };

	// Store
	return knot_db_lmdb_api()->insert(txn, &key, &val, 0);
}

/*! \brief Reads timers for persistent events. */
static int read_timers(knot_db_txn_t *txn, const zone_t *zone, time_t *timers)
{
	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	knot_db_val_t key = { .len = knot_dname_size(zone->name), .data = zone->name };
	knot_db_val_t val;

	int ret = db_api->find(txn, &key, &val, 0);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return ret;
	}

	clear_timers(timers);
	if (ret == KNOT_ENOENT) {
		return KNOT_EOK;
	}

	const size_t stored_event_count = val.len / EVENT_KEY_PAIR_SIZE;
	size_t offset = 0;
	for (size_t i = 0; i < stored_event_count; ++i) {
		const uint8_t db_key = ((uint8_t *)val.data)[offset];
		offset += 1;
		if (known_event_key(db_key)) {
			const zone_event_type_t event = key_to_event_id[db_key];
			timers[event] =
				(time_t)wire_read_u64((uint8_t *)val.data + offset);
		}
		offset += sizeof(uint64_t);
	}

	return KNOT_EOK;
}

int open_timers_db(const char *path, knot_db_t **timer_db)
{
	if (path == NULL || timer_db == NULL) {
		return KNOT_EINVAL;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	if (db_api == NULL) {
		return KNOT_ENOTSUP;
	}

	struct knot_db_lmdb_opts opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	opts.mapsize = (size_t)TIMER_MAPSIZE * 1024 * 1024;
	opts.path = path;

	return db_api->init(timer_db, NULL, &opts);
}

void close_timers_db(knot_db_t *timer_db)
{
	if (timer_db == NULL) {
		return;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	db_api->deinit(timer_db);
}

int read_zone_timers(knot_db_t *timer_db, const zone_t *zone, time_t *timers)
{
	if (timer_db == NULL) {
		clear_timers(timers);
		return KNOT_EOK;
	}

	if (zone == NULL || timers == NULL) {
		return KNOT_EINVAL;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	knot_db_txn_t txn;
	int ret = db_api->txn_begin(timer_db, &txn, KNOT_DB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = read_timers(&txn, zone, timers);
	db_api->txn_abort(&txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

int write_timer_db(knot_db_t *timer_db, knot_zonedb_t *zone_db)
{
	if (timer_db == NULL) {
		return KNOT_EOK;
	}

	if (zone_db == NULL) {
		return KNOT_EINVAL;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	knot_db_txn_t txn;
	int ret = db_api->txn_begin(timer_db, &txn, KNOT_DB_SORTED);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_zonedb_foreach(zone_db, store_timers, &txn);

	return db_api->txn_commit(&txn);
}

int sweep_timer_db(knot_db_t *timer_db, knot_zonedb_t *zone_db)
{
	if (timer_db == NULL) {
		return KNOT_EOK;
	}

	if (zone_db == NULL) {
		return KNOT_EINVAL;
	}

	const knot_db_api_t *db_api = knot_db_lmdb_api();
	assert(db_api);

	knot_db_txn_t txn;
	int ret = db_api->txn_begin(timer_db, &txn, KNOT_DB_SORTED);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (db_api->count(&txn) == 0) {
		db_api->txn_abort(&txn);
		return KNOT_EOK;
	}

	knot_db_iter_t *it = db_api->iter_begin(&txn, 0);
	if (it == NULL) {
		db_api->txn_abort(&txn);
		return KNOT_ERROR;
	}

	while (it) {
		knot_db_val_t key;
		ret = db_api->iter_key(it, &key);
		if (ret != KNOT_EOK) {
			db_api->txn_abort(&txn);
			return ret;
		}
		const knot_dname_t *dbkey = (const knot_dname_t *)key.data;
		if (!knot_zonedb_find(zone_db, dbkey)) {
			// Delete obsolete timers
			db_api->del(&txn, &key);
		}

		it = db_api->iter_next(it);
	}
	db_api->iter_finish(it);

	return db_api->txn_commit(&txn);
}
