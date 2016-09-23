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

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/requestor.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/contents.h"
#include "knot/zone/serial.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "libknot/libknot.h"
#include "contrib/trim.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/lists.h"
#include "contrib/ucw/mempool.h"

#define JOURNAL_SUFFIX	".diff.db"

static void free_ddns_queue(zone_t *z)
{
	ptrnode_t *node = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(node, nxt, z->ddns_queue) {
		knot_request_free(node->d, NULL);
	}
	ptrlist_free(&z->ddns_queue, NULL);
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

	// Journal lock
	pthread_mutex_init(&zone->journal_lock, NULL);

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

	knot_dname_free(&zone->name, NULL);

	free_ddns_queue(zone);
	pthread_mutex_destroy(&zone->ddns_lock);
	pthread_mutex_destroy(&zone->journal_lock);

	/* Control update. */
	zone_control_clear(zone);

	/* Free preferred master. */
	pthread_mutex_destroy(&zone->preferred_lock);
	free(zone->preferred_master);

	/* Free zone contents. */
	zone_contents_deep_free(&zone->contents);

	conf_deactivate_modules(&zone->query_modules, &zone->query_plan);

	free(zone);
	*zone_ptr = NULL;
}

int zone_change_store(conf_t *conf, zone_t *zone, changeset_t *change)
{
	if (conf == NULL || zone == NULL || change == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val = conf_zone_get(conf, C_MAX_JOURNAL_SIZE, zone->name);
	int64_t ixfr_fslimit = conf_int(&val);
	char *journal_file = conf_journalfile(conf, zone->name);

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_store_changeset(change, journal_file, ixfr_fslimit);
	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal is full, flushing");

		/* Transaction rolled back, journal released, we may flush. */
		ret = zone_flush_journal(conf, zone);
		if (ret == KNOT_EOK) {
			ret = journal_store_changeset(change, journal_file, ixfr_fslimit);
		}
	}
	pthread_mutex_unlock(&zone->journal_lock);

	free(journal_file);

	return ret;
}

int zone_changes_store(conf_t *conf, zone_t *zone, list_t *chgs)
{
	if (conf == NULL || zone == NULL || chgs == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val = conf_zone_get(conf, C_MAX_JOURNAL_SIZE, zone->name);
	int64_t ixfr_fslimit = conf_int(&val);
	char *journal_file = conf_journalfile(conf, zone->name);

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_store_changesets(chgs, journal_file, ixfr_fslimit);
	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal is full, flushing");

		/* Transaction rolled back, journal released, we may flush. */
		ret = zone_flush_journal(conf, zone);
		if (ret == KNOT_EOK) {
			ret = journal_store_changesets(chgs, journal_file, ixfr_fslimit);
		}

	}
	pthread_mutex_unlock(&zone->journal_lock);

	free(journal_file);

	return ret;
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

	return timers->soa_expire > 0 && timers->last_refresh > 0 &&
	       timers->last_refresh + timers->soa_expire <= time(NULL);
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
			if (sockaddr_net_match((struct sockaddr *)&remote.addr,
			                       (struct sockaddr *)zone->preferred_master,
			                       -1)) {
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

int zone_master_try(conf_t *conf, zone_t *zone, zone_master_cb callback,
                    void *callback_data, const char *err_str)
{
	if (conf == NULL || zone == NULL || callback == NULL || err_str == NULL) {
		return KNOT_EINVAL;
	}

	/* Try the preferred server. */

	conf_remote_t preferred = { { AF_UNSPEC } };
	if (preferred_master(conf, zone, &preferred) == KNOT_EOK) {
		int ret = callback(conf, zone, &preferred, callback_data);
		if (ret == KNOT_EOK) {
			return ret;
		}
	}

	/* Try all the other servers. */

	bool success = false;

	conf_val_t masters = conf_zone_get(conf, C_MASTER, zone->name);
	while (masters.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &masters);
		size_t addr_count = conf_val_count(&addr);

		for (size_t i = 0; i < addr_count; i++) {
			conf_remote_t master = conf_remote(conf, &masters, i);
			if (preferred.addr.ss_family != AF_UNSPEC &&
			    sockaddr_net_match((struct sockaddr *)&master.addr,
			                       (struct sockaddr *)&preferred.addr,
			                       -1)) {
				preferred.addr.ss_family = AF_UNSPEC;
				continue;
			}
			int ret = callback(conf, zone, &master, callback_data);
			if (ret == KNOT_EOK) {
				success = true;
				break;
			}
		}

		if (!success) {
			log_zone_warning(zone->name, "%s, remote '%s' not usable",
			                 err_str, conf_str(&masters));
		}

		conf_val_next(&masters);
	}

	return success ? KNOT_EOK : KNOT_ENOMASTER;
}

int zone_flush_journal(conf_t *conf, zone_t *zone)
{
	if (conf == NULL || zone == NULL || zone_contents_is_empty(zone->contents)) {
		return KNOT_EINVAL;
	}

	bool force = zone->flags & ZONE_FORCE_FLUSH;
	zone->flags &= ~ZONE_FORCE_FLUSH;

	/* Check for disabled zonefile synchronization. */
	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	if (conf_int(&val) < 0 && !force) {
		return KNOT_EOK;
	}

	/* Check for difference against zonefile serial. */
	zone_contents_t *contents = zone->contents;
	uint32_t serial_to = zone_contents_serial(contents);
	if (!force && zone->zonefile.exists && zone->zonefile.serial == serial_to) {
		return KNOT_EOK; /* No differences. */
	}

	char *zonefile = conf_zonefile(conf, zone->name);

	/* Synchronize journal. */
	int ret = zonefile_write(zonefile, contents);
	if (ret != KNOT_EOK) {
		log_zone_warning(zone->name, "failed to update zone file (%s)",
		                 knot_strerror(ret));
		free(zonefile);
		return ret;
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
		return KNOT_EACCES;
	}

	free(zonefile);

	char *journal_file = conf_journalfile(conf, zone->name);

	/* Update zone file serial and journal. */
	zone->zonefile.exists = true;
	zone->zonefile.mtime = st.st_mtime;
	zone->zonefile.serial = serial_to;
	journal_mark_synced(journal_file);

	free(journal_file);

	/* Trim extra heap. */
	mem_trim();

	return ret;
}

int zone_update_enqueue(zone_t *zone, knot_pkt_t *pkt, struct process_query_param *param)
{
	if (zone == NULL || pkt == NULL || param == NULL) {
		return KNOT_EINVAL;
	}

	/* Create serialized request. */
	struct knot_request *req = malloc(sizeof(struct knot_request));
	if (req == NULL) {
		return KNOT_ENOMEM;
	}
	memset(req, 0, sizeof(struct knot_request));

	/* Copy socket and request. */
	req->fd = dup(param->socket);
	memcpy(&req->remote, param->remote, sizeof(struct sockaddr_storage));

	req->query = knot_pkt_new(NULL, pkt->max_size, NULL);
	int ret = knot_pkt_copy(req->query, pkt);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&req->query);
		free(req);
		return ret;
	}

	pthread_mutex_lock(&zone->ddns_lock);

	/* Enqueue created request. */
	ptrlist_add(&zone->ddns_queue, req, NULL);
	++zone->ddns_queue_size;

	pthread_mutex_unlock(&zone->ddns_lock);

	/* Schedule UPDATE event. */
	zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

size_t zone_update_dequeue(zone_t *zone, list_t *updates)
{
	if (zone == NULL || updates == NULL) {
		return 0;
	}

	pthread_mutex_lock(&zone->ddns_lock);
	if (EMPTY_LIST(zone->ddns_queue)) {
		/* Lost race during reload. */
		pthread_mutex_unlock(&zone->ddns_lock);
		return 0;
	}

	*updates = zone->ddns_queue;
	size_t update_count = zone->ddns_queue_size;
	init_list(&zone->ddns_queue);
	zone->ddns_queue_size = 0;

	pthread_mutex_unlock(&zone->ddns_lock);

	return update_count;
}
