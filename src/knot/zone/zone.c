/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/module.h"
#include "knot/dnssec/kasp/kasp_db.h"
#include "knot/events/replan.h"
#include "knot/journal/journal_read.h"
#include "knot/journal/journal_write.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/requestor.h"
#include "knot/updates/zone-update.h"
#include "knot/server/server.h"
#include "knot/zone/contents.h"
#include "knot/zone/serial.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "libknot/libknot.h"
#include "contrib/sockaddr.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/lists.h"
#include "contrib/ucw/mempool.h"

#define JOURNAL_LOCK_MUTEX (&zone->journal_lock)
#define JOURNAL_LOCK_RW pthread_mutex_lock(JOURNAL_LOCK_MUTEX);
#define JOURNAL_UNLOCK_RW pthread_mutex_unlock(JOURNAL_LOCK_MUTEX);

static void free_ddns_queue(zone_t *zone)
{
	ptrnode_t *node, *nxt;
	WALK_LIST_DELSAFE(node, nxt, zone->ddns_queue) {
		knot_request_free(node->d, NULL);
	}
	ptrlist_free(&zone->ddns_queue, NULL);
}

/*!
 * \param allow_empty_zone useful when need to flush journal but zone is not yet loaded
 * ...in this case we actually don't have to do anything because the zonefile is current,
 * but we must mark the journal as flushed
 */
static int flush_journal(conf_t *conf, zone_t *zone, bool allow_empty_zone, bool verbose)
{
	/*! @note Function expects nobody will change zone contents meanwhile. */

	assert(zone);

	int ret = KNOT_EOK;
	zone_journal_t j = zone_journal(zone);

	bool force = zone_get_flag(zone, ZONE_FORCE_FLUSH, true);

	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);

	if (zone_contents_is_empty(zone->contents)) {
		if (allow_empty_zone && journal_is_existing(j)) {
			ret = journal_set_flushed(j);
		} else {
			ret = KNOT_EEMPTYZONE;
		}
		goto flush_journal_replan;
	}

	/* Check for disabled zonefile synchronization. */
	if (sync_timeout < 0 && !force) {
		if (verbose) {
			log_zone_warning(zone->name, "zonefile synchronization disabled, "
			                             "use force command to override it");
		}
		return KNOT_EOK;
	}

	/* Check for updated zone. */
	zone_contents_t *contents = zone->contents;
	uint32_t serial_to = zone_contents_serial(contents);
	if (!force && zone->zonefile.exists && zone->zonefile.serial == serial_to &&
	    !zone->zonefile.retransfer && !zone->zonefile.resigned) {
		ret = KNOT_EOK; /* No differences. */
		goto flush_journal_replan;
	}

	char *zonefile = conf_zonefile(conf, zone->name);

	/* Synchronize journal. */
	ret = zonefile_write(zonefile, contents);
	if (ret != KNOT_EOK) {
		log_zone_warning(zone->name, "failed to update zone file (%s)",
		                 knot_strerror(ret));
		free(zonefile);
		goto flush_journal_replan;
	}

	if (zone->zonefile.exists) {
		log_zone_info(zone->name, "zone file updated, serial %u -> %u",
		              zone->zonefile.serial, serial_to);
	} else {
		log_zone_info(zone->name, "zone file updated, serial %u",
		              serial_to);
	}

	/* Update zone version. */
	struct stat st;
	if (stat(zonefile, &st) < 0) {
		log_zone_warning(zone->name, "failed to update zone file (%s)",
		                 knot_strerror(knot_map_errno()));
		free(zonefile);
		ret = KNOT_EACCES;
		goto flush_journal_replan;
	}

	free(zonefile);

	/* Update zone file attributes. */
	zone->zonefile.exists = true;
	zone->zonefile.mtime = st.st_mtim;
	zone->zonefile.serial = serial_to;
	zone->zonefile.resigned = false;
	zone->zonefile.retransfer = false;

	/* Flush journal. */
	if (journal_is_existing(j)) {
		ret = journal_set_flushed(j);
		if (ret != KNOT_EOK) {
			goto flush_journal_replan;
		}
	}

flush_journal_replan:
	/* Plan next journal flush after proper period. */
	zone->timers.last_flush = time(NULL);
	if (sync_timeout > 0) {
		time_t next_flush = zone->timers.last_flush + sync_timeout;
		zone_events_schedule_at(zone, ZONE_EVENT_FLUSH, 0,
		                              ZONE_EVENT_FLUSH, next_flush);
	}

	return ret;
}

zone_t* zone_new(const knot_dname_t *name)
{
	zone_t *zone = malloc(sizeof(zone_t));
	if (zone == NULL) {
		return NULL;
	}
	memset(zone, 0, sizeof(zone_t));

	zone->name = knot_dname_copy(name, NULL);
	if (zone->name == NULL) {
		free(zone);
		return NULL;
	}

	// DDNS
	pthread_mutex_init(&zone->ddns_lock, NULL);
	zone->ddns_queue_size = 0;
	init_list(&zone->ddns_queue);

	knot_sem_init(&zone->cow_lock, 1);

	// Preferred master lock
	pthread_mutex_init(&zone->preferred_lock, NULL);

	// Initialize events
	zone_events_init(zone);

	// Initialize query modules list.
	init_list(&zone->query_modules);

	return zone;
}

void zone_control_clear(zone_t *zone)
{
	if (zone == NULL) {
		return;
	}

	zone_update_clear(zone->control_update);
	free(zone->control_update);
	zone->control_update = NULL;
}

void zone_free(zone_t **zone_ptr)
{
	if (zone_ptr == NULL || *zone_ptr == NULL) {
		return;
	}

	zone_t *zone = *zone_ptr;

	zone_events_deinit(zone);

	knot_dname_free(zone->name, NULL);

	free_ddns_queue(zone);
	pthread_mutex_destroy(&zone->ddns_lock);

	knot_sem_destroy(&zone->cow_lock);

	/* Control update. */
	zone_control_clear(zone);

	free(zone->catalog_gen);
	catalog_update_free(zone->cat_members);

	/* Free preferred master. */
	pthread_mutex_destroy(&zone->preferred_lock);
	free(zone->preferred_master);

	/* Free zone contents. */
	zone_contents_deep_free(zone->contents);

	conf_deactivate_modules(&zone->query_modules, &zone->query_plan);

	free(zone);
	*zone_ptr = NULL;
}

void zone_reset(conf_t *conf, zone_t *zone)
{
	if (zone == NULL) {
		return;
	}

	zone_contents_t *old_contents = zone_switch_contents(zone, NULL);
	conf_reset_modules(conf, &zone->query_modules, &zone->query_plan); // includes synchronize_rcu()
	zone_contents_deep_free(old_contents);
	if (zone_expired(zone)) {
		replan_from_timers(conf, zone);
	} else {
		zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
	}
}

knot_lmdb_db_t *zone_journaldb(const zone_t *zone)
{
	return &zone->server->journaldb;
}

knot_lmdb_db_t *zone_kaspdb(const zone_t *zone)
{
	return &zone->server->kaspdb;
}

catalog_t *zone_catalog(const zone_t *zone)
{
	return &zone->server->catalog;
}

catalog_update_t *zone_catalog_upd(const zone_t *zone)
{
	return &zone->server->catalog_upd;
}

int zone_change_store(conf_t *conf, zone_t *zone, changeset_t *change, changeset_t *extra)
{
	if (conf == NULL || zone == NULL || change == NULL) {
		return KNOT_EINVAL;
	}

	zone_journal_t j = { zone_journaldb(zone), zone->name, conf };

	int ret = journal_insert(j, change, extra);
	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal is full, flushing");

		/* Transaction rolled back, journal released, we may flush. */
		ret = flush_journal(conf, zone, true, false);
		if (ret == KNOT_EOK) {
			ret = journal_insert(j, change, extra);
		}
	}

	return ret;
}

int zone_changes_clear(conf_t *conf, zone_t *zone)
{
	if (conf == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	return journal_scrape_with_md(zone_journal(zone), true);
}

int zone_in_journal_store(conf_t *conf, zone_t *zone, zone_contents_t *new_contents)
{
	if (conf == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	if (new_contents == NULL) {
		return KNOT_EEMPTYZONE;
	}

	zone_journal_t j = { zone_journaldb(zone), zone->name, conf };

	int ret = journal_insert_zone(j, new_contents);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone stored to journal, serial %u",
		              zone_contents_serial(new_contents));
	}

	return ret;
}

int zone_flush_journal(conf_t *conf, zone_t *zone, bool verbose)
{
	if (conf == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	return flush_journal(conf, zone, false, verbose);
}

bool zone_journal_has_zij(zone_t *zone)
{
	bool exists = false, zij = false;
	(void)journal_info(zone_journal(zone), &exists, NULL, &zij, NULL, NULL, NULL, NULL, NULL);
	return exists && zij;
}

zone_contents_t *zone_switch_contents(zone_t *zone, zone_contents_t *new_contents)
{
	if (zone == NULL) {
		return NULL;
	}

	zone_contents_t *old_contents;
	zone_contents_t **current_contents = &zone->contents;
	old_contents = rcu_xchg_pointer(current_contents, new_contents);

	return old_contents;
}

bool zone_is_slave(conf_t *conf, const zone_t *zone)
{
	if (conf == NULL || zone == NULL) {
		return false;
	}

	conf_val_t val = conf_zone_get(conf, C_MASTER, zone->name);
	return conf_val_count(&val) > 0 ? true : false;
}

void zone_set_preferred_master(zone_t *zone, const struct sockaddr_storage *addr)
{
	if (zone == NULL || addr == NULL) {
		return;
	}

	pthread_mutex_lock(&zone->preferred_lock);
	free(zone->preferred_master);
	zone->preferred_master = malloc(sizeof(struct sockaddr_storage));
	*zone->preferred_master = *addr;
	pthread_mutex_unlock(&zone->preferred_lock);
}

void zone_clear_preferred_master(zone_t *zone)
{
	if (zone == NULL) {
		return;
	}

	pthread_mutex_lock(&zone->preferred_lock);
	free(zone->preferred_master);
	zone->preferred_master = NULL;
	pthread_mutex_unlock(&zone->preferred_lock);
}

void zone_set_flag(zone_t *zone, zone_flag_t flag)
{
	if (zone == NULL) {
		return;
	}

	pthread_mutex_lock(&zone->preferred_lock); // this mutex seems OK to be reused for this
	zone->flags |= flag;
	pthread_mutex_unlock(&zone->preferred_lock);

	if (flag & ZONE_IS_CATALOG) {
		zone->is_catalog_flag = true;
	}
}

zone_flag_t zone_get_flag(zone_t *zone, zone_flag_t flag, bool clear)
{
	if (zone == NULL) {
		return 0;
	}

	pthread_mutex_lock(&zone->preferred_lock);
	zone_flag_t res = (zone->flags & flag);
	if (clear && res) {
		zone->flags &= ~flag;
	}
	assert(((bool)(zone->flags & ZONE_IS_CATALOG)) == zone->is_catalog_flag);
	pthread_mutex_unlock(&zone->preferred_lock);

	return res;
}

const knot_rdataset_t *zone_soa(const zone_t *zone)
{
	if (!zone || zone_contents_is_empty(zone->contents)) {
		return NULL;
	}

	return node_rdataset(zone->contents->apex, KNOT_RRTYPE_SOA);
}

bool zone_expired(const zone_t *zone)
{
	if (!zone) {
		return false;
	}

	const zone_timers_t *timers = &zone->timers;

	return timers->last_refresh > 0 && timers->soa_expire > 0 &&
	       timers->last_refresh + timers->soa_expire <= time(NULL);
}

static void time_set_default(time_t *time, time_t value)
{
	assert(time);

	if (*time == 0) {
		*time = value;
	}
}

void zone_timers_sanitize(conf_t *conf, zone_t *zone)
{
	assert(conf);
	assert(zone);

	time_t now = time(NULL);

	// replace SOA expire if we have better knowledge
	if (!zone_contents_is_empty(zone->contents)) {
		const knot_rdataset_t *soa = zone_soa(zone);
		zone->timers.soa_expire = knot_soa_expire(soa->rdata);
	}

	// assume now if we don't know when we flushed
	time_set_default(&zone->timers.last_flush, now);

	if (zone_is_slave(conf, zone)) {
		// assume now if we don't know
		time_set_default(&zone->timers.last_refresh, now);
		time_set_default(&zone->timers.next_refresh, now);
	} else {
		// invalidate if we don't have a master
		zone->timers.last_refresh = 0;
		zone->timers.next_refresh = 0;
		zone->timers.last_refresh_ok = false;
	}
}

/*!
 * \brief Get preferred zone master while checking its existence.
 */
int static preferred_master(conf_t *conf, zone_t *zone, conf_remote_t *master)
{
	pthread_mutex_lock(&zone->preferred_lock);

	if (zone->preferred_master == NULL) {
		pthread_mutex_unlock(&zone->preferred_lock);
		return KNOT_ENOENT;
	}

	conf_val_t masters = conf_zone_get(conf, C_MASTER, zone->name);
	while (masters.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &masters);
		size_t addr_count = conf_val_count(&addr);

		for (size_t i = 0; i < addr_count; i++) {
			conf_remote_t remote = conf_remote(conf, &masters, i);
			if (sockaddr_net_match(&remote.addr, zone->preferred_master, -1)) {
				*master = remote;
				pthread_mutex_unlock(&zone->preferred_lock);
				return KNOT_EOK;
			}
		}

		conf_val_next(&masters);
	}

	pthread_mutex_unlock(&zone->preferred_lock);

	return KNOT_ENOENT;
}

static void log_try_addr_error(const zone_t *zone, const char *remote_name,
                               const struct sockaddr_storage *remote_addr,
                               const char *err_str, int ret)
{
	char addr_str[SOCKADDR_STRLEN] = { 0 };
	sockaddr_tostr(addr_str, sizeof(addr_str), remote_addr);
	log_zone_debug(zone->name, "%s%s%s, address %s, failed (%s)", err_str,
	               (remote_name != NULL ? ", remote " : ""),
	               (remote_name != NULL ? remote_name : ""),
	               addr_str, knot_strerror(ret));
}

int zone_master_try(conf_t *conf, zone_t *zone, zone_master_cb callback,
                    void *callback_data, const char *err_str)
{
	if (conf == NULL || zone == NULL || callback == NULL || err_str == NULL) {
		return KNOT_EINVAL;
	}

	zone_master_fallback_t fallback = { true, true };

	/* Try the preferred server. */

	conf_remote_t preferred = { { AF_UNSPEC } };
	if (preferred_master(conf, zone, &preferred) == KNOT_EOK) {
		int ret = callback(conf, zone, &preferred, callback_data, &fallback);
		if (ret == KNOT_EOK) {
			return ret;
		} else if (!fallback.remote) {
			return ret; // Local error.
		}

		log_try_addr_error(zone, NULL, &preferred.addr, err_str, ret);

		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), &preferred.addr);
		log_zone_warning(zone->name, "%s, address %s not usable",
		                 err_str, addr_str);
	}

	/* Try all the other servers. */

	bool success = false;

	conf_val_t masters = conf_zone_get(conf, C_MASTER, zone->name);
	while (masters.code == KNOT_EOK && fallback.remote) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &masters);
		size_t addr_count = conf_val_count(&addr);

		bool tried = false;
		fallback.address = true;
		for (size_t i = 0; i < addr_count && fallback.address; i++) {
			conf_remote_t master = conf_remote(conf, &masters, i);
			if (preferred.addr.ss_family != AF_UNSPEC &&
			    sockaddr_net_match(&master.addr, &preferred.addr, -1)) {
				preferred.addr.ss_family = AF_UNSPEC;
				continue;
			}

			tried = true;
			int ret = callback(conf, zone, &master, callback_data, &fallback);
			if (ret == KNOT_EOK) {
				success = true;
				break;
			} else if (!fallback.remote) {
				return ret; // Local error.
			}

			log_try_addr_error(zone, conf_str(&masters), &master.addr,
			                   err_str, ret);
		}

		if (!success && tried) {
			log_zone_warning(zone->name, "%s, remote %s not usable",
			                 err_str, conf_str(&masters));
		}

		conf_val_next(&masters);
	}

	return success ? KNOT_EOK : KNOT_ENOMASTER;
}

int zone_dump_to_dir(conf_t *conf, zone_t *zone, const char *dir)
{
	if (zone == NULL || dir == NULL) {
		return KNOT_EINVAL;
	}

	size_t dir_len = strlen(dir);
	if (dir_len == 0) {
		return KNOT_EINVAL;
	}

	char *zonefile = conf_zonefile(conf, zone->name);
	char *zonefile_basename = strrchr(zonefile, '/');
	if (zonefile_basename == NULL) {
		zonefile_basename = zonefile;
	}

	size_t target_length = strlen(zonefile_basename) + dir_len + 2;
	char target[target_length];
	(void)snprintf(target, target_length, "%s/%s", dir, zonefile_basename);
	if (strcmp(target, zonefile) == 0) {
		free(zonefile);
		return KNOT_EDENIED;
	}
	free(zonefile);

	return zonefile_write(target, zone->contents);
}

int zone_set_master_serial(zone_t *zone, uint32_t serial)
{
	return kasp_db_store_serial(zone_kaspdb(zone), zone->name, KASPDB_SERIAL_MASTER, serial);
}

int zone_get_master_serial(zone_t *zone, uint32_t *serial)
{
	return kasp_db_load_serial(zone_kaspdb(zone), zone->name, KASPDB_SERIAL_MASTER, serial);
}

int zone_set_lastsigned_serial(zone_t *zone, uint32_t serial)
{
	return kasp_db_store_serial(zone_kaspdb(zone), zone->name, KASPDB_SERIAL_LASTSIGNED, serial);
}

int zone_get_lastsigned_serial(zone_t *zone, uint32_t *serial)
{
	return kasp_db_load_serial(zone_kaspdb(zone), zone->name, KASPDB_SERIAL_LASTSIGNED, serial);
}

int slave_zone_serial(zone_t *zone, conf_t *conf, uint32_t *serial)
{
	int ret = KNOT_EOK;
	assert(zone->contents != NULL);
	*serial = zone_contents_serial(zone->contents);

	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		ret = zone_get_master_serial(zone, serial);
	}

	return ret;
}
