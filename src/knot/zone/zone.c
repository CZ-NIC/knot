/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
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

knot_dynarray_define(notifailed_rmt, notifailed_rmt_hash, DYNARRAY_VISIBILITY_NORMAL);

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
	bool user_flush = zone_get_flag(zone, ZONE_USER_FLUSH, true);

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

	val = conf_zone_get(conf, C_ZONE_BACKEND, zone->name);
	unsigned backend = conf_opt(&val);

	rcu_read_lock();
	struct stat st = { 0 };
	zone_contents_t *contents = zone->contents;
	uint32_t serial_to = zone_contents_serial(contents);
	if (!force && !user_flush &&
	    zone->zonefile.exists && zone->zonefile.serial == serial_to &&
	    !zone->zonefile.retransfer && !zone->zonefile.resigned) {
		ret = KNOT_EOK; /* No differences. */
		rcu_read_unlock();
		goto flush_journal_replan;
	}

	if (backend == ZONE_BACKEND_FILE) {
		char *zonefile = conf_zonefile(conf, zone->name);

		ret = zonefile_write_skip(zonefile, contents, conf);
		rcu_read_unlock();
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
		if (stat(zonefile, &st) < 0) {
			log_zone_warning(zone->name, "failed to update zone file (%s)",
			                 knot_strerror(knot_map_errno()));
			free(zonefile);
			ret = KNOT_EACCES;
			goto flush_journal_replan;
		}

		free(zonefile);
	} else {
#ifdef ENABLE_REDIS
		redisContext *rdb = zone_rdb_connect(conf);
		if (rdb == NULL) {
			ret = KNOT_ECONN;
			rcu_read_unlock();
			goto flush_journal_replan;
		}

		ret = zone_rdb_write(rdb, contents);
		rcu_read_unlock();
		if (ret != KNOT_EOK) {
			log_zone_warning(zone->name, "failed to update database (%s)",
			                 knot_strerror(ret));
			goto flush_journal_replan;
		}
#else
		ret = KNOT_ENOTSUP;
#endif
	}

	/* Update zone file attributes. */
	zone->zonefile.exists = true;
	zone->zonefile.mtime = st.st_mtim;
	zone->zonefile.serial = serial_to;
	zone->zonefile.resigned = false;
	zone->zonefile.retransfer = false;

	/* Flush journal. */
	if (journal_is_existing(j)) {
		ret = journal_set_flushed(j);
	}

flush_journal_replan:
	/* Plan next journal flush after proper period. */
	zone->timers.last_flush = time(NULL);
	if (sync_timeout > 0) {
		time_t next_flush = zone->timers.last_flush + sync_timeout;
		zone_events_schedule_at(zone, ZONE_EVENT_FLUSH, (time_t)0,
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

	pthread_mutex_init(&zone->cu_lock, NULL);
	knot_sem_init(&zone->cow_lock, 1);

	// Preferred master lock
	pthread_mutex_init(&zone->preferred_lock, NULL);

	// Initialize events
	zone_events_init(zone);

	// Initialize query modules list.
	init_list(&zone->query_modules);

	init_list(&zone->reverse_from);
	init_list(&zone->internal_notify);

	ATOMIC_INIT(zone->backup_ctx, NULL);

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

	if (zone->update_clear_thr) {
		pthread_join(zone->update_clear_thr, NULL);
	}

	/* Free zone contents. Possible wait for XFRout lock. */
	zone_contents_deep_free(zone->contents);

	knot_dname_free(zone->name, NULL);

	free_ddns_queue(zone);
	pthread_mutex_destroy(&zone->ddns_lock);

	pthread_mutex_destroy(&zone->cu_lock);
	knot_sem_destroy(&zone->cow_lock);

	/* Control update. */
	zone_control_clear(zone);

	free(zone->catalog_gen);
	catalog_update_free(zone->cat_members);

	/* Free preferred master. */
	pthread_mutex_destroy(&zone->preferred_lock);
	free(zone->preferred_master);

	conf_deactivate_modules(&zone->query_modules, &zone->query_plan);

	ptrlist_free(&zone->reverse_from, NULL);
	ptrlist_free(&zone->internal_notify, NULL);

	ATOMIC_DEINIT(zone->backup_ctx);

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

#define RETURN_IF_FAILED(str, exception) \
{ \
	if (ret != KNOT_EOK && ret != (exception)) { \
		errors = true; \
		log_zone_error(zone->name, \
		               "failed to purge %s (%s)", (str), knot_strerror(ret)); \
		if (exit_immediately) { \
			return ret; \
		} \
	} \
}

// UBSAN type punning workaround
static bool dname_cmp_sweep_wrap(const uint8_t *zone, void *data)
{
	return knot_dname_cmp((const knot_dname_t *)zone, (const knot_dname_t *)data) != 0;
}

int selective_zone_purge(conf_t *conf, zone_t *zone, purge_flag_t params)
{
	if (conf == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	int ret;
	bool errors = false;
	bool exit_immediately = !(params & PURGE_ZONE_BEST);

	// Purge the zone timers.
	if (params & PURGE_ZONE_TIMERS) {
		bool member = (zone->catalog_gen != NULL);
		zone->timers = (zone_timers_t) {
			.catalog_member = member ? zone->timers.catalog_member : 0
		};
		if (member) {
			ret = zone_timers_write(&zone->server->timerdb, zone->name,
			                        &zone->timers);
		} else {
			ret = zone_timers_sweep(&zone->server->timerdb,
			                        dname_cmp_sweep_wrap, zone->name);
		}
		zone_timers_sanitize(conf, zone);
		zone->zonefile.bootstrap_cnt = 0;
		RETURN_IF_FAILED("timers", KNOT_ENOENT);
	}

	// Purge the zone file.
	if (params & PURGE_ZONE_ZONEFILE) {
		conf_val_t sync;
		if ((params & PURGE_ZONE_NOSYNC) ||
		    (sync = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name),
		     conf_int(&sync) > -1)) {
			char *zonefile = conf_zonefile(conf, zone->name);
			ret = (unlink(zonefile) == -1 ? knot_map_errno() : KNOT_EOK);
			free(zonefile);
			RETURN_IF_FAILED("zone file", KNOT_ENOENT);
		}
	}

	// Purge the zone journal.
	if (params & PURGE_ZONE_JOURNAL) {
		ret = journal_scrape_with_md(zone_journal(zone), true);
		RETURN_IF_FAILED("journal", KNOT_ENOENT);
	}

	// Purge KASP DB.
	if (params & PURGE_ZONE_KASPDB) {
		ret = knot_lmdb_open(zone_kaspdb(zone));
		if (ret == KNOT_EOK) {
			ret = kasp_db_delete_all(zone_kaspdb(zone), zone->name);
		}
		RETURN_IF_FAILED("KASP DB", KNOT_ENOENT);
	}

	// Purge Catalog.
	if (params & PURGE_ZONE_CATALOG) {
		ret = catalog_zone_purge(zone->server, conf, zone->name);
		RETURN_IF_FAILED("catalog", KNOT_EOK);
	}

	if (errors) {
		return KNOT_ERROR;
	}

	if ((params & PURGE_ZONE_LOG) ||
	    (params & PURGE_ZONE_DATA) == PURGE_ZONE_DATA) {
		log_zone_notice(zone->name, "zone purged");
	}

	return KNOT_EOK;
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

static int journal_insert_flush(conf_t *conf, zone_t *zone,
                                changeset_t *change, changeset_t *extra,
                                const zone_diff_t *diff)
{
	zone_journal_t j = { zone_journaldb(zone), zone->name, conf };

	int ret = journal_insert(j, change, extra, diff);
	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal, flushing the zone to allow old changesets cleanup to free space");

		/* Transaction rolled back, journal released, we may flush. */
		ret = flush_journal(conf, zone, true, false);
		if (ret == KNOT_EOK) {
			ret = journal_insert(j, change, extra, diff);
		}
	}

	return ret;
}

int zone_change_store(conf_t *conf, zone_t *zone, changeset_t *change, changeset_t *extra)
{
	if (conf == NULL || zone == NULL || change == NULL) {
		return KNOT_EINVAL;
	}

	return journal_insert_flush(conf, zone, change, extra, NULL);
}

int zone_diff_store(conf_t *conf, zone_t *zone, const zone_diff_t *diff)
{
	if (conf == NULL || zone == NULL || diff == NULL) {
		return KNOT_EINVAL;
	}

	return journal_insert_flush(conf, zone, NULL, NULL, diff);
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

void zone_notifailed_clear(zone_t *zone)
{
	pthread_mutex_lock(&zone->preferred_lock);
	notifailed_rmt_dynarray_free(&zone->notifailed);
	pthread_mutex_unlock(&zone->preferred_lock);
}

void zone_schedule_notify(zone_t *zone, time_t delay)
{
	zone_notifailed_clear(zone);
	zone_events_schedule_at(zone, ZONE_EVENT_NOTIFY, time(NULL) + delay);
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
	return (val.code == KNOT_EOK) ? true : false; // Reference item cannot be empty.
}

void zone_set_preferred_master(zone_t *zone, const struct sockaddr_storage *addr)
{
	if (zone == NULL || addr == NULL) {
		return;
	}

	pthread_mutex_lock(&zone->preferred_lock);
	free(zone->preferred_master);
	zone->preferred_master = malloc(sizeof(*zone->preferred_master));
	memcpy(zone->preferred_master, addr, sockaddr_len(addr));
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

void zone_set_last_master(zone_t *zone, const struct sockaddr_storage *addr)
{
	if (zone == NULL) {
		return;
	}

	if (addr == NULL) {
		memset(&zone->timers.last_master, 0, sizeof(zone->timers.last_master));
	} else {
		memcpy(&zone->timers.last_master, addr, sizeof(zone->timers.last_master));
	}
	zone->timers.master_pin_hit = 0;
}

static void set_flag(zone_t *zone, zone_flag_t flag, bool remove)
{
	if (zone == NULL) {
		return;
	}

	pthread_mutex_lock(&zone->preferred_lock); // this mutex seems OK to be reused for this
	zone->flags = remove ? (zone->flags & ~flag) : (zone->flags | flag);
	pthread_mutex_unlock(&zone->preferred_lock);

	if (flag & ZONE_IS_CATALOG) {
		zone->is_catalog_flag = !remove;
	}
}

void zone_set_flag(zone_t *zone, zone_flag_t flag)
{
	return set_flag(zone, flag, false);
}

void zone_unset_flag(zone_t *zone, zone_flag_t flag)
{
	return set_flag(zone, flag, true);
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

uint32_t zone_soa_expire(const zone_t *zone)
{
	const knot_rdataset_t *soa = zone_soa(zone);
	return soa == NULL ? 0 : knot_soa_expire(soa->rdata);
}

bool zone_expired(const zone_t *zone)
{
	if (!zone) {
		return false;
	}

	const zone_timers_t *timers = &zone->timers;

	return timers->next_expire > 0 && timers->next_expire <= time(NULL);
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

	// assume now if we don't know when we flushed
	time_set_default(&zone->timers.last_flush, now);

	if (zone_is_slave(conf, zone)) {
		// assume now if we don't know
		time_set_default(&zone->timers.next_refresh, now);
		if (zone->is_catalog_flag) {
			zone->timers.next_expire = 0;
		}
	} else {
		// invalidate if we don't have a master
		zone->timers.last_refresh = 0;
		zone->timers.next_refresh = 0;
		zone->timers.last_refresh_ok = false;
		zone->timers.next_expire = 0;
	}
}

static int try_remote(conf_t *conf, zone_t *zone, zone_master_cb callback,
                      void *callback_data, const char *err_str, const char *remote_id,
                      conf_val_t *remote, zone_master_fallback_t *fallback,
                      const char *remote_prefix)
{
	int ret = KNOT_ERROR;

	conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, remote);
	size_t addr_count = conf_val_count(&addr);
	assert(addr_count > 0);
	assert(fallback->address);

	for (size_t i = 0; i < addr_count && fallback->address; i++) {
		conf_remote_t master = conf_remote(conf, remote, i);
		ret = callback(conf, zone, &master, callback_data, fallback);
		if (ret == KNOT_EOK) {
			return ret;
		}

		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), &master.addr);
		log_zone_info(zone->name, "%s, %sremote %s, address %s, failed (%s)",
		              err_str, remote_prefix, remote_id, addr_str, knot_strerror(ret));
	}

	log_zone_warning(zone->name, "%s, %sremote %s not usable",
	                 err_str, remote_prefix, remote_id);

	return ret;
}

int zone_master_try(conf_t *conf, zone_t *zone, zone_master_cb callback,
                    void *callback_data, const char *err_str)
{
	if (conf == NULL || zone == NULL || callback == NULL || err_str == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val = conf_zone_get(conf, C_MASTER_PIN_TOL, zone->name);
	uint32_t pin_tolerance = conf_int(&val);

	/* Find last and preferred master in conf. */

	const char *last_id = NULL, *preferred_id = NULL;
	conf_val_t last = { 0 }, preferred = { 0 };
	int idx = 0, last_idx = -1, preferred_idx = -1;

	conf_val_t masters = conf_zone_get(conf, C_MASTER, zone->name);
	conf_mix_iter_t iter;
	conf_mix_iter_init(conf, &masters, &iter);
	pthread_mutex_lock(&zone->preferred_lock);
	while (iter.id->code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, iter.id);
		size_t addr_count = conf_val_count(&addr);

		for (size_t i = 0; i < addr_count; i++) {
			conf_remote_t remote = conf_remote(conf, iter.id, i);
			if (zone->preferred_master != NULL &&
			    sockaddr_net_match(&remote.addr, zone->preferred_master, -1)) {
				preferred_id = conf_str(iter.id);
				preferred = *iter.id;
				preferred_idx = idx;
			}
			if (pin_tolerance > 0 &&
			    sockaddr_net_match(&remote.addr, (struct sockaddr_storage *)&zone->timers.last_master, -1)) {
				last_id = conf_str(iter.id);
				last = *iter.id;
				last_idx = idx;
			}
		}

		idx++;
		conf_mix_iter_next(&iter);
	}
	pthread_mutex_unlock(&zone->preferred_lock);

	int ret = KNOT_EOK;

	/* Try the preferred server. */

	if (preferred_idx >= 0) {
		zone_master_fallback_t fallback = {
			true, true, preferred_idx == last_idx, pin_tolerance
		};
		ret = try_remote(conf, zone, callback, callback_data, err_str,
		                 preferred_id, &preferred, &fallback, "notifier ");
		if (ret == KNOT_EOK || !fallback.remote) {
			return ret; // Success or local error.
		}
	}

	/* Try the last server. */

	if (last_idx >= 0 && last_idx != preferred_idx) {
		zone_master_fallback_t fallback = {
			true, true, true, pin_tolerance
		};
		ret = try_remote(conf, zone, callback, callback_data, err_str,
		                 last_id, &last, &fallback, "pinned ");
		if (!fallback.remote) {
			return ret; // Local error.
		}
	}

	/* Try all the other servers. */

	conf_val_reset(&masters);
	conf_mix_iter_init(conf, &masters, &iter);
	zone_master_fallback_t fallback = { true, true, false, pin_tolerance };
	for (idx = 0; iter.id->code == KNOT_EOK && fallback.remote; idx++) {
		if (idx != last_idx && idx != preferred_idx) {
			fallback.address = true;
			conf_val_t remote = *iter.id;
			ret = try_remote(conf, zone, callback, callback_data, err_str,
			                 conf_str(&remote), &remote, &fallback, "");
			if (!fallback.remote) {
				break; // Local error.
			}
		}
		conf_mix_iter_next(&iter);
	}

	return ret == KNOT_EOK ? KNOT_EOK : KNOT_ENOMASTER;
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

	return zonefile_write_skip(target, zone->contents, conf);
}

void zone_local_notify_subscribe(zone_t *zone, zone_t *subscribe)
{
	ptrlist_add(&zone->internal_notify, subscribe, NULL);
}

void zone_local_notify(zone_t *zone)
{
	ptrnode_t *n;
	WALK_LIST(n, zone->internal_notify) {
		zone_events_schedule_now(n->d, ZONE_EVENT_LOAD);
	}
}

int zone_set_master_serial(zone_t *zone, uint32_t serial)
{
	return kasp_db_store_serial(zone_kaspdb(zone), zone->name, KASPDB_SERIAL_MASTER, serial);
}

int zone_get_master_serial(zone_t *zone, uint32_t *serial)
{
	return kasp_db_load_serial(zone_kaspdb(zone), zone->name, KASPDB_SERIAL_MASTER, serial);
}

void zone_set_lastsigned_serial(zone_t *zone, uint32_t serial)
{
	zone->timers.last_signed_serial = serial;
	zone->timers.last_signed_s_flags = LAST_SIGNED_SERIAL_FOUND | LAST_SIGNED_SERIAL_VALID;
}

int zone_get_lastsigned_serial(zone_t *zone, uint32_t *serial)
{
	if (!(zone->timers.last_signed_s_flags & LAST_SIGNED_SERIAL_FOUND)) {
		// backwards compatibility: it used to be stored in KASP DB, moved to timers for performance
		return kasp_db_load_serial(zone_kaspdb(zone), zone->name, KASPDB_SERIAL_LASTSIGNED, serial);
	}
	if (!(zone->timers.last_signed_s_flags & LAST_SIGNED_SERIAL_VALID)) {
		return KNOT_ENOENT;
	}
	*serial = zone->timers.last_signed_serial;
	return KNOT_EOK;
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
