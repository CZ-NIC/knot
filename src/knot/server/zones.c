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

/*!
 * \brief Update ACL list from configuration.
 *
 * \param acl Pointer to existing or NULL ACL.
 * \param acl_list List of remotes from configuration.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOMEM on failed memory allocation.
 */
static int zones_set_acl(acl_t **acl, list* acl_list)
{
	if (!acl || !acl_list) {
		return KNOT_EINVAL;
	}

	/* Truncate old ACL. */
	acl_delete(acl);

	/* Create new ACL. */
	*acl = acl_new(ACL_DENY, 0);
	if (!*acl) {
		return KNOT_ENOMEM;
	}

	/* Load ACL rules. */
	conf_remote_t *r = 0;
	WALK_LIST(r, *acl_list) {

		/* Initialize address. */
		sockaddr_t addr;
		conf_iface_t *cfg_if = r->remote;
		int ret = sockaddr_set(&addr, cfg_if->family,
				       cfg_if->address, cfg_if->port);

		/* Load rule. */
		if (ret > 0) {
			acl_create(*acl, &addr, ACL_ACCEPT);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Load zone to zone database.
 *
 * \param zonedb Zone database to load the zone into.
 * \param zone_name Zone name (owner of the apex node).
 * \param source Path to zone file source.
 * \param filename Path to requested compiled zone file.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_EZONEINVAL
 */
static int zones_load_zone(dnslib_zonedb_t *zonedb, const char *zone_name,
			   const char *source, const char *filename)
{
	dnslib_zone_t *zone = NULL;

	// Check path
	if (filename) {
		debug_server("Parsing zone database '%s'\n", filename);
		zloader_t *zl = dnslib_zload_open(filename);
		if (!zl) {
			log_server_error("Compiled db '%s' is too old, "
			                 " please recompile.\n",
			                 filename);
			return KNOT_EZONEINVAL;
		}

		// Check if the db is up-to-date
		int src_changed = strcmp(source, zl->source) != 0;
		if (src_changed || dnslib_zload_needs_update(zl)) {
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
/*!
 * \brief Fill the new database with zones.
 *
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param zone_conf Zone configuration.
 * \param db_old Old zone database.
 * \param db_new New zone database.
 *
 * \return Number of inserted zones.
 */
static int zones_insert_zones(const list *zone_conf,
                              const dnslib_zonedb_t *db_old,
                              dnslib_zonedb_t *db_new)
{
	node *n;
	int inserted = 0;
	// for all zones in the configuration
	WALK_LIST(n, *zone_conf) {
		conf_zone_t *z = (conf_zone_t *)n;
		// convert the zone name into a domain name
		dnslib_dname_t *zone_name = dnslib_dname_new_from_str(z->name,
		                                         strlen(z->name), NULL);
		if (zone_name == NULL) {
			log_server_error("Error creating domain name from zone"
			                 " name\n");
			return inserted;
		}

		debug_zones("Inserting zone %s into the new database.\n",
		            z->name);

		// try to find the zone in the current zone db
		dnslib_zone_t *zone = dnslib_zonedb_find_zone(db_old,
		                                              zone_name);
		if (zone != NULL) {
			// if found, just insert the zone into the new zone db
			debug_zones("Found in old database, copying to new.\n");
			int ret = dnslib_zonedb_add_zone(db_new, zone);
			if (ret != KNOT_EOK) {
				log_server_error("Error adding old zone to"
				                 " the new database: %s\n",
				                 knot_strerror(ret));
			} else {
				++inserted;
			}
		} else {
			// if not found, the zone must be loaded
			debug_zones("Not found in old database, loading...\n");
			int ret = zones_load_zone(db_new, z->name,
						  z->file, z->db);
			if (ret != KNOT_EOK) {
				log_server_error("Error loading new zone to"
				                 " the new database: %s\n",
				                 knot_strerror(ret));
			} else {
				// Find the new zone
				zone = dnslib_zonedb_find_zone(db_new,
							       zone_name);
				++inserted;
			}
			// unused return value, if not loaded, just continue
		}

		// Update ACLs
		if (zone) {
			debug_zones("Updating zone ACLs.");
			zones_set_acl(&zone->acl.xfr_in, &z->acl.xfr_in);
			zones_set_acl(&zone->acl.xfr_out, &z->acl.xfr_out);
			zones_set_acl(&zone->acl.notify_in, &z->acl.notify_in);
			zones_set_acl(&zone->acl.notify_out, &z->acl.notify_out);
		}

		dnslib_dname_free(&zone_name);
	}
	return inserted;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Remove zones present in the configuration from the old database.
 *
 * After calling this function, the old zone database should contain only zones
 * that should be completely deleted.
 *
 * \param zone_conf Zone configuration.
 * \param db_old Old zone database to remove zones from.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
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
/* API functions                                                              */
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

	log_server_info("Loading %d zones...\n", conf->zones_count);

	// Insert all required zones to the new zone DB.
	int inserted = zones_insert_zones(&conf->zones, *db_old, db_new);

	log_server_info("Loaded %d out of %d zones.\n", inserted,
	                conf->zones_count);

	if (inserted != conf->zones_count) {
		log_server_warning("Not all the zones were loaded.\n");
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
	int ret = zones_remove_zones(&conf->zones, *db_old);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Unlock RCU, messing with any data will not affect us now
	rcu_read_unlock();

	debug_zones("Old database is empty (%p): %s\n", (*db_old)->zones,
	            skip_is_empty((*db_old)->zones) ? "yes" : "no");

	return KNOT_EOK;
}
