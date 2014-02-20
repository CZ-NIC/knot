/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <assert.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "knot/server/zone-load.h"
#include "knot/server/zones.h"
#include "knot/zone/zone-load.h"
#include "libknot/dname.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"
#include "libknot/rdata.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonedb.h"
#include "common/descriptor.h"

/* Constants */

#define XFRIN_BOOTSTRAP_DELAY 2000 /*!< AXFR bootstrap avg. delay */

/*- zone file status --------------------------------------------------------*/

/*!
 * \brief Zone file status.
 */
typedef enum {
	ZONE_STATUS_NOT_FOUND = 0,  //!< Zone file does not exist.
	ZONE_STATUS_FOUND_NEW,      //!< Zone file exists, not loaded yet.
	ZONE_STATUS_FOUND_CURRENT,  //!< Zone file exists, same as loaded.
	ZONE_STATUS_FOUND_UPDATED,  //!< Zone file exists, newer than loaded.
} zone_status_t;

/*!
 * \brief Check zone file status.
 *
 * \param old_zone  Previous instance of the zone (can be NULL).
 * \param filename  File name of zone file.
 *
 * \return Zone status.
 */
static zone_status_t zone_file_status(const zone_t *old_zone,
                                      const char *filename)
{
	struct stat zf_stat = { 0 };
	int result = stat(filename, &zf_stat);

	if (result == -1) {
		return ZONE_STATUS_NOT_FOUND;
	} else if (old_zone == NULL) {
		return ZONE_STATUS_FOUND_NEW;
	} else if (old_zone->zonefile_mtime == zf_stat.st_mtime) {
		return ZONE_STATUS_FOUND_CURRENT;
	} else {
		return ZONE_STATUS_FOUND_UPDATED;
	}
}

/*- zone loading/updating ---------------------------------------------------*/

/*!
 * \brief Handle retrieval of zone if zone file does not exist.
 *
 * \param conf      New configuration for given zone.
 *
 * \return New zone, NULL if bootstrap not possible.
 */
static zone_t *bootstrap_zone(conf_zone_t *conf)
{
	assert(conf);

	bool bootstrap = !EMPTY_LIST(conf->acl.xfr_in);
	if (!bootstrap) {
		return load_zone_file(conf); /* No master for this zone, fallback. */
	}

	zone_t *new_zone = zone_new(conf);
	if (!new_zone) {
		log_zone_error("Bootstrap of zone '%s' failed: %s\n",
		               conf->name, knot_strerror(KNOT_ENOMEM));
		return NULL;
	}

	/* Initialize bootstrap timer. */
	new_zone->xfr_in.bootstrap_retry = knot_random_uint32_t() % XFRIN_BOOTSTRAP_DELAY;

	return new_zone;
}

zone_t *load_zone_file(conf_zone_t *conf)
{
	assert(conf);

	/* Open zone file for parsing. */
	zloader_t zl;
	int ret = zonefile_open(&zl, conf);
	if (ret != KNOT_EOK) {
		log_zone_error("Failed to open zone file '%s': %s\n",
		               conf->file, knot_strerror(ret));
		return NULL;
	}

	struct stat st;
	if (stat(conf->file, &st) < 0) {
		/* Go silently and reset mtime to 0. */
		memset(&st, 0, sizeof(struct stat));
	}

	/* Load the zone contents. */
	knot_zone_contents_t *zone_contents = zonefile_load(&zl);
	zonefile_close(&zl);

	/* Check the loader result. */
	if (zone_contents == NULL) {
		log_zone_error("Failed to load zone file '%s'.\n", conf->file);
		return NULL;
	}

	/* Create the new zone. */
	zone_t *zone = zone_new((conf_zone_t *)conf);
	if (zone == NULL) {
		log_zone_error("Failed to create zone '%s': %s\n",
		               conf->name, knot_strerror(KNOT_ENOMEM));
		knot_zone_contents_deep_free(&zone_contents);
		return NULL;
	}

	/* Link zone contents to zone. */
	zone->contents = zone_contents;

	/* Save the timestamp from the zone db file. */
	zone->zonefile_mtime = st.st_mtime;
	zone->zonefile_serial = knot_zone_serial(zone->contents);

	return zone;
}

/*!
 * \brief Create a new zone structure according to documentation, but reuse
 *        existing zone content.
 */
static zone_t *preserve_zone(conf_zone_t *conf, const zone_t *old_zone)
{
	assert(old_zone);

	zone_t *new_zone = zone_new(conf);
	if (!new_zone) {
		log_zone_error("Preserving current zone '%s' failed: %s\n",
		               conf->name, knot_strerror(KNOT_ENOMEM));
		return NULL;
	}

	new_zone->contents = old_zone->contents;

	return new_zone;
}

/*!
 * \brief Log message about loaded zone (name, status, serial).
 *
 * \param zone       Zone structure.
 * \param zone_name  Printable name of the zone.
 * \param status     Zone file status.
 */
static void log_zone_load_info(const zone_t *zone, const char *zone_name,
                               zone_status_t status)
{
	assert(zone);
	assert(zone_name);

	const char *action = NULL;

	switch (status) {
	case ZONE_STATUS_NOT_FOUND:     action = "bootstrapped";  break;
	case ZONE_STATUS_FOUND_NEW:     action = "loaded";        break;
	case ZONE_STATUS_FOUND_CURRENT: action = "is up-to-date"; break;
	case ZONE_STATUS_FOUND_UPDATED: action = "reloaded";      break;
	}
	assert(action);

	int64_t serial = 0;
	if (zone->contents && zone->contents->apex) {
		const knot_rrset_t *soa;
		soa = knot_node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
		serial = knot_rdata_soa_serial(soa);
	}

	log_zone_info("Zone '%s' %s (serial %" PRId64 ")\n", zone_name, action, serial);
}

/*!
 * \brief Load or reload the zone.
 *
 * \param old_zone  Already loaded zone (can be NULL).
 * \param conf      Zone configuration.
 * \param server    Name server.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static zone_t *create_zone(zone_t *old_zone, conf_zone_t *conf, server_t *server)
{
	assert(conf);

	zone_status_t zstatus = zone_file_status(old_zone, conf->file);
	zone_t *new_zone = NULL;

	switch (zstatus) {
	case ZONE_STATUS_NOT_FOUND:
		new_zone = bootstrap_zone(conf);
		break;
	case ZONE_STATUS_FOUND_NEW:
	case ZONE_STATUS_FOUND_UPDATED:
		new_zone = load_zone_file(conf);
		break;
	case ZONE_STATUS_FOUND_CURRENT:
		new_zone = preserve_zone(conf, old_zone);
		break;
	default:
		assert(0);
	}

	if (!new_zone) {
		log_server_error("Failed to load zone '%s'.\n", conf->name);
		return NULL;
	}

	/* Initialize zone timers. */
	zone_timers_create(new_zone, &server->sched);

	log_zone_load_info(new_zone, conf->name, zstatus);

	return new_zone;
}

/*!
 * \brief Load/reload the zone, apply journal, sign it and schedule XFR sync.
 *
 * \param[in]  old_zone  Old zone (if loaded).
 * \param[in]  conf      Zone configuration.
 * \param[in]  server    Name server structure.
 *
 * \return Updated zone on success, NULL otherwise.
 */
static zone_t* update_zone(zone_t *old_zone, conf_zone_t *conf, server_t *server)
{
	assert(conf);

	int result = KNOT_ERROR;

	// Load zone.
	zone_t *new_zone = create_zone(old_zone, conf, server);
	if (!new_zone) {
		return NULL;
	}

	bool new_content = (old_zone == NULL || old_zone->contents != new_zone->contents);

	result = zones_journal_apply(new_zone);
	if (result != KNOT_EOK && result != KNOT_ERANGE && result != KNOT_ENOENT) {
		log_zone_error("Zone '%s', failed to apply changes from journal: %s\n",
		               conf->name, knot_strerror(result));
		goto fail;
	}

	result = zones_do_diff_and_sign(conf, new_zone, old_zone, new_content);
	if (result != KNOT_EOK) {
		log_zone_error("Zone '%s', failed to create diff and/or sign "
		               "the zone: %s. The server will continue to serve"
		               " the old zone.\n",
		               conf->name, knot_strerror(result));
		goto fail;
	}

fail:
	assert(new_zone);

	if (result == KNOT_EOK) {
		return new_zone;
	} else {
		/* Preserved zone, don't free the shared contents. */
		if (!new_content) {
			new_zone->contents = NULL;
		}

		/* Disconnect config, caller is responsible for it. */
		new_zone->conf = NULL;
		zone_free(&new_zone);
	}

	return NULL;
}

/*!
 * \brief Check zone configuration constraints.
 */
static int update_zone_postcond(zone_t *new_zone, const conf_t *config)
{
	/* Bootstrapped zone, no checks apply. */
	if (new_zone->contents == NULL) {
		return KNOT_EOK;
	}

	/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
	if (knot_zone_contents_is_signed(new_zone->contents)) {
		unsigned edns_dnssec_min = EDNS_MIN_DNSSEC_PAYLOAD;
		if (config->max_udp_payload < edns_dnssec_min) {
			log_zone_warning("EDNS payload lower than %uB for "
			                 "DNSSEC-enabled zone '%s'.\n",
			                 edns_dnssec_min, new_zone->conf->name);
		}
	}

	/* Check NSEC3PARAM state if present. */
	int result = knot_zone_contents_load_nsec3param(new_zone->contents);
	if (result != KNOT_EOK) {
		log_zone_error("NSEC3 signed zone has invalid or no "
			       "NSEC3PARAM record.\n");
		return result;
	}

	return KNOT_EOK;
}

/*! \brief Context for threaded zone loader. */
typedef struct {
	const struct conf_t *config;
	server_t      *server;
	knot_zonedb_t *db_old;
	knot_zonedb_t *db_new;
	pthread_mutex_t lock;
} zone_loader_ctx_t;

/*! Thread entrypoint for loading zones. */
static int zone_loader_thread(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	zone_t *zone = NULL;
	conf_zone_t *zone_config = NULL;
	zone_loader_ctx_t *ctx = (zone_loader_ctx_t *)thread->data;
	for(;;) {
		/* Fetch zone configuration from the list. */
		pthread_mutex_lock(&ctx->lock);
		if (EMPTY_LIST(ctx->config->zones)) {
			pthread_mutex_unlock(&ctx->lock);
			break;
		}

		/* Disconnect from the list and start processing. */
		zone_config = HEAD(ctx->config->zones);
		rem_node(&zone_config->n);
		pthread_mutex_unlock(&ctx->lock);

		/* Retrive old zone (if exists). */
		knot_dname_t *apex = knot_dname_from_str(zone_config->name);
		if (!apex) {
			return KNOT_ENOMEM;
		}
		zone_t *old_zone = knot_zonedb_find(ctx->db_old, apex);
		knot_dname_free(&apex);

		/* Update the zone. */
		zone = update_zone(old_zone, zone_config, ctx->server);
		if (zone == NULL) {
			conf_free_zone(zone_config);
			continue;
		}

		/* Check updated zone post-conditions. */
		int ret = update_zone_postcond(zone, ctx->config);

		/* Insert into database if properly loaded. */
		if (ret == KNOT_EOK) {
			pthread_mutex_lock(&ctx->lock);
			if (zone != NULL) {
				ret = knot_zonedb_insert(ctx->db_new, zone);
			}
			pthread_mutex_unlock(&ctx->lock);
		}

		/* Check for any failure. */
		if (ret != KNOT_EOK && zone) {
			/* Preserved zone, don't free the shared contents. */
			if (old_zone && old_zone->contents == zone->contents) {
				zone->contents = NULL;
			}

			zone_free(&zone);
		}
	}

	return KNOT_EOK;
}

static int zone_loader_destruct(dthread_t *thread)
{
	knot_crypto_cleanup_thread();
	return KNOT_EOK;
}

/*!
 * \brief Fill the new database with zones.
 *
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param server Name server instance.
 * \param conf Server configuration.
 *
 * \return Number of inserted zones.
 */
static knot_zonedb_t *load_zonedb(server_t *server, const conf_t *conf)
{
	/* Initialize threaded loader. */
	zone_loader_ctx_t ctx = {0};
	ctx.config = conf;
	ctx.server = server;
	ctx.db_old = server->zone_db;
	ctx.db_new = knot_zonedb_new(conf->zones_count);
	if (ctx.db_new == NULL) {
		return NULL;
	}

	if (conf->zones_count == 0) {
		return ctx.db_new;
	}

	if (pthread_mutex_init(&ctx.lock, NULL) < 0) {
		knot_zonedb_free(&ctx.db_new);
		return NULL;
	}

	/* Initialize threads. */
	size_t thread_count = MIN(conf->zones_count, dt_optimal_size());
	dt_unit_t *unit = NULL;
	unit = dt_create(thread_count, &zone_loader_thread,
	                          &zone_loader_destruct, &ctx);
	if (unit != NULL) {
		/* Start loading. */
		dt_start(unit);
		dt_join(unit);
		dt_delete(&unit);
	} else {
		knot_zonedb_free(&ctx.db_new);
		ctx.db_new = NULL;
	}

	pthread_mutex_destroy(&ctx.lock);
	return ctx.db_new;
}

/*!
 * \brief Remove old zones and zone database.
 *
 * \note Zone may be preserved in the new zone database, in this case
 *       new and old zone share the contents. Shared content is not freed.
 *
 * \param db_new New zone database.
 * \param db_old Old zone database.
  */
static int remove_old_zonedb(const knot_zonedb_t *db_new, knot_zonedb_t *db_old)
{
	if (db_old == NULL) {
		return KNOT_EOK; /* Nothing to free. */
	}

	knot_zonedb_iter_t it;
	knot_zonedb_iter_begin(db_new, &it);

	while(!knot_zonedb_iter_finished(&it)) {
		zone_t *new_zone = knot_zonedb_iter_val(&it);
		zone_t *old_zone = knot_zonedb_find(db_old, new_zone->name);

		/* If the zone exists in both new and old database and the contents
		 * didn't change. We must invalidate the pointer in the old zone
		 * to preserve the contents.
		 */
		if (old_zone && old_zone->contents == new_zone->contents) {
			old_zone->contents = NULL;
		}

		knot_zonedb_iter_next(&it);
	}

	synchronize_rcu();

	/* Delete all deprecated zones and delete the old database. */
	knot_zonedb_deep_free(&db_old);

	return KNOT_EOK;
}

/*- public API functions ----------------------------------------------------*/

/*!
 * \brief Update zone database according to configuration.
 */
int load_zones_from_config(const conf_t *conf, struct server_t *server)
{
	/* Check parameters */
	if (conf == NULL || server == NULL) {
		return KNOT_EINVAL;
	}

	/* Freeze zone timers. */
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_timers_freeze);
	}

	/* Insert all required zones to the new zone DB. */
	/*! \warning RCU must not be locked as some contents switching will
	             be required. */
	knot_zonedb_t *db_new = load_zonedb(server, conf);
	if (db_new == NULL) {
		log_server_warning("Failed to load zones.\n");
		return KNOT_ENOMEM;
	} else {
		size_t loaded = knot_zonedb_size(db_new);
		log_server_info("Loaded %zu out of %d zones.\n",
		                loaded, conf->zones_count);
		if (loaded != conf->zones_count) {
			log_server_warning("Not all the zones were loaded.\n");
		}
	}

	/* Rebuild zone database search stack. */
	knot_zonedb_build_index(db_new);

	/* Switch the databases. */
	knot_zonedb_t *db_old = rcu_xchg_pointer(&server->zone_db, db_new);

	/* Wait for readers to finish reading old zone database. */
	synchronize_rcu();

	/* Thaw zone events now that the database is published. */
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_timers_thaw);
		knot_zonedb_foreach(server->zone_db, zones_schedule_notify, server);
	}

	/*
	 * Remove all zones present in the new DB from the old DB.
	 * No new thread can access these zones in the old DB, as the
	 * databases are already switched.
	 */
	return remove_old_zonedb(db_new, db_old);
}
