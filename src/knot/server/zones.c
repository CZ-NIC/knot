#include <sys/stat.h>

#include "knot/server/zones.h"
#include "knot/other/error.h"
#include "knot/conf/conf.h"
#include "dnslib/zonedb.h"
#include "common/lists.h"
#include "dnslib/dname.h"
#include "dnslib/zone.h"
#include "knot/other/log.h"
#include "dnslib/zone-load.h"
#include "knot/other/debug.h"

/*----------------------------------------------------------------------------*/

static int zones_insert_zones(const list *zone_conf,
                             const dnslib_zonedb_t *db_old,
                             dnslib_zonedb_t *db_new)
{
	node *n;
	// for all zones in the configuration
	WALK_LIST(n, *zone_conf) {
		conf_zone_t *z = (conf_zone_t *)n;
		// convert the zone name into a domain name
		dnslib_dname_t *zone_name = dnslib_dname_new_from_str(z->name,
		                                         strlen(z->name), NULL);
		if (zone_name == NULL) {
			log_server_error("Error creating domain name from zone"
			                 " name\n");
			return KNOT_ERROR;
		}

		debug_zones("Inserting zone %s into the new database.\n",
		            z->name);

		// try to find the zone in the current zone db
		dnslib_zone_t *zone = dnslib_zonedb_find_zone(db_old,
		                                              zone_name);
		if (zone != NULL) {
			// if found, just insert the zone into the new zone db
			debug_zones("Found in old database, copying to new.\n");
			(void)dnslib_zonedb_add_zone(db_new, zone);
		} else {
			// if not found, the zone must be loaded
			debug_zones("Not found in old database, loading...\n");
			(void)zones_load_zone(db_new, z->name, z->db);
			// unused return value, if not loaded, just continue
		}

		dnslib_dname_free(&zone_name);
	}
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_remove_zones(const list *zone_conf, dnslib_zonedb_t *db_old)
{
	node *n;
	// for all zones in the configuration
	WALK_LIST(n, *zone_conf) {
		conf_zone_t *z = (conf_zone_t *)n;
		// convert the zone name into a domain name
		dnslib_dname_t *zone_name = dnslib_dname_new_from_str(z->name,
		                                         strlen(z->name), NULL);
		if (zone_name == NULL) {
			log_server_error("Error creating domain name from zone"
			                 " name\n");
			return KNOT_ERROR;
		}
		debug_zones("Removing zone %s from the old database.\n",
		            z->name);
		// remove the zone from the old zone db, but do not delete it
		dnslib_zonedb_remove_zone(db_old, zone_name, 0);

		dnslib_dname_free(&zone_name);
	}
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_load_zone(dnslib_zonedb_t *zonedb, const char *zone_name,
                    const char *filename)
{
	dnslib_zone_t *zone = NULL;

	// Check path
	if (filename) {
		debug_server("Parsing zone database '%s'\n", filename);
		zloader_t *zl = dnslib_zload_open(filename);
		if (!zl && errno == EILSEQ) {
			log_server_error("Compiled db '%s' is too old, "
			                 " please recompile.\n",
			                 filename);
			return KNOT_EZONEINVAL;
		}

		// Check if the db is up-to-date
		if (dnslib_zload_needs_update(zl)) {
			log_server_warning("Database for zone '%s' is not "
			                   "up-to-date. Please recompile.\n",
			                   zone_name);
		}

		zone = dnslib_zload_load(zl);
		dnslib_zload_close(zl);
		if (zone) {
			if (dnslib_zonedb_add_zone(zonedb, zone) != 0){
				dnslib_zone_deep_free(&zone, 0);
				zone = 0;
			}
		}

		if (!zone) {
			log_server_error("Failed to load "
					 "db '%s' for zone '%s'.\n",
					 filename, zone_name);
			return KNOT_EZONEINVAL;
		}
	} else {
		/* db is null. */
		return KNOT_EINVAL;
	}

//	dnslib_zone_dump(zone, 1);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_update_db_from_config(const conf_t *conf, ns_nameserver_t *ns,
                               dnslib_zonedb_t **db_old)
{
	// Check parameters
	if (conf == NULL || ns == NULL) {
		return KNOT_EINVAL;
	}

	// Lock RCU to ensure noone will deallocate any data under our hands.
	rcu_read_lock();

	// Grab a pointer to the old database
	*db_old = ns->zone_db;
	if (*db_old == NULL) {
		log_server_error("Missing zone database in nameserver structure"
		                 ".\n");
		return KNOT_ERROR;
	}

	// Create new zone DB
	dnslib_zonedb_t *db_new = dnslib_zonedb_new();
	if (db_new == NULL) {
		return KNOT_ERROR;
	}

	// Insert all required zones to the new zone DB.
	int ret = zones_insert_zones(&conf->zones, *db_old, db_new);
	if (ret != KNOT_EOK) {
		return ret;
	}

	debug_zones("Old db in nameserver: %p, old db stored: %p, new db: %p\n",
	            ns->zone_db, *db_old, db_new);

	// Switch the databases.
	(void)rcu_xchg_pointer(&ns->zone_db, db_new);

	debug_zones("db in nameserver: %p, old db stored: %p, new db: %p\n",
	            ns->zone_db, *db_old, db_new);

	/*
	 *  Remove all zones present in the new DB from the old DB.
	 *  No new thread can access these zones in the old DB, as the
	 *  databases are already switched.
	 */
	ret = zones_remove_zones(&conf->zones, *db_old);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Unlock RCU, messing with any data will not affect us now
	rcu_read_unlock();

	debug_zones("Old database is empty (%p): %s\n", (*db_old)->zones,
	            skip_is_empty((*db_old)->zones) ? "yes" : "no");

	return KNOT_EOK;
}
