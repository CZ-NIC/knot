/* Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <assert.h>
#include <string.h>
#include <sys/stat.h>

#include "libknot/descriptor.h"
#include "common-knot/evsched.h"
#include "common-knot/lists.h"
#include "common-knot/trim.h"
#include "knot/zone/node.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/contents.h"
#include "knot/updates/apply.h"
#include "knot/nameserver/requestor.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/dnssec/random.h"
#include "libknot/util/utils.h"
#include "libknot/rrtype/soa.h"

static void free_ddns_queue(zone_t *z)
{
	struct request_data *n = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, z->ddns_queue) {
		close(n->fd);
		knot_pkt_free(&n->query);
		rem_node((node_t *)n);
		free(n);
	}
}

zone_t* zone_new(conf_zone_t *conf)
{
	if (!conf) {
		return NULL;
	}

	zone_t *zone = malloc(sizeof(zone_t));
	if (zone == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(zone, 0, sizeof(zone_t));

	zone->name = knot_dname_from_str_alloc(conf->name);
	knot_dname_to_lower(zone->name);
	if (zone->name == NULL) {
		free(zone);
		ERR_ALLOC_FAILED;
		return NULL;
	}

	// Configuration
	zone->conf = conf;

	// DDNS
	pthread_mutex_init(&zone->ddns_lock, NULL);
	zone->ddns_queue_size = 0;
	init_list(&zone->ddns_queue);

	// Journal lock
	pthread_mutex_init(&zone->journal_lock, NULL);

	// Initialize events
	zone_events_init(zone);

	return zone;
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

	/* Free assigned config. */
	conf_free_zone(zone->conf);

	/* Free zone contents. */
	zone_contents_deep_free(&zone->contents);

	free(zone);
	*zone_ptr = NULL;
}

int zone_change_store(zone_t *zone, changeset_t *change)
{
	assert(zone);
	assert(change);

	conf_zone_t *conf = zone->conf;

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_store_changeset(change, conf->ixfr_db, conf->ixfr_fslimit);
	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal is full, flushing");

		/* Transaction rolled back, journal released, we may flush. */
        printf("APODW TO KALESA1\n");
		ret = zone_flush_journal(zone);
		if (ret == KNOT_EOK) {
			ret = journal_store_changeset(change, conf->ixfr_db, conf->ixfr_fslimit);
		}
	}
	pthread_mutex_unlock(&zone->journal_lock);

	return ret;
}

int zone_changes_store(zone_t *zone, list_t *chgs)
{
	assert(zone);
	assert(chgs);

	conf_zone_t *conf = zone->conf;

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_store_changesets(chgs, conf->ixfr_db, conf->ixfr_fslimit);

	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal is full, flushing");

		/* Transaction rolled back, journal released, we may flush. */
        printf("APODW TO KALESA2\n");

		ret = zone_flush_journal(zone);
		if (ret == KNOT_EOK) {
			ret = journal_store_changesets(chgs, conf->ixfr_db, conf->ixfr_fslimit);
		}
	}
	pthread_mutex_unlock(&zone->journal_lock);

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

const conf_iface_t *zone_master(const zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	if (EMPTY_LIST(zone->conf->acl.xfr_in)) {
		return NULL;
	}

	conf_remote_t *master = HEAD(zone->conf->acl.xfr_in);
	return master->remote;
}

bool zone_is_slave(const zone_t *zone)
{
	return zone && !EMPTY_LIST(zone->conf->acl.xfr_in);
}

/*!
 * \brief Get zone preferred master while checking it's existence.
 *
 * It is possible that the preferred master will change during the function
 * execution. We can ignore this race. In the worst case, the preferred master
 * won't be found and we will try all servers in default order.
 */
static const conf_remote_t *preferred_master(const zone_t *zone)
{
	if (!zone->preferred_master) {
		return NULL;
	}

	conf_remote_t *master = NULL;
	WALK_LIST(master, zone->conf->acl.xfr_in) {
		if (master->remote == zone->preferred_master) {
			return master;
		}
	}

	return NULL;
}

int zone_master_try(zone_t *zone, zone_master_cb callback, void *callback_data)
{
	if (!zone || EMPTY_LIST(zone->conf->acl.xfr_in)) {
		return KNOT_EINVAL;
	}

	/* Try the preferred server. */

	const conf_remote_t *preferred = preferred_master(zone);
	if (preferred) {
		int ret = callback(zone, preferred->remote, callback_data);
		if (ret == KNOT_EOK) {
			return ret;
		}
	}

	/* Try all the other servers. */

	conf_remote_t *master = NULL;
	WALK_LIST(master, zone->conf->acl.xfr_in) {
		if (master == preferred) {
			continue;
		}

		int ret = callback(zone, master->remote, callback_data);
		if (ret == KNOT_EOK) {
			return KNOT_EOK;
		}
	}

	return KNOT_ENOMASTER;
}

int zone_flush_journal(zone_t *zone)
{
	/*! @note Function expects nobody will change zone contents meanwile. */

	if (zone == NULL || zone_contents_is_empty(zone->contents)) {
        printf("TESTING FLUSH -> CONTENTS ARE EMTPY\n");
		return KNOT_EINVAL;
	}

	/* Check for difference against zonefile serial. */
	zone_contents_t *contents = zone->contents;
	uint32_t serial_to = zone_contents_serial(contents);
	if (zone->zonefile_serial == serial_to) {
		return KNOT_EOK; /* No differences. */
	}

	/* Synchronize journal. */
	conf_zone_t *conf = zone->conf;
	int ret = zonefile_write(conf->file, contents);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone file updated, serial %u -> %u",
		              zone->zonefile_serial, serial_to);
	} else {
		log_zone_warning(zone->name, "failed to update zone file (%s)",
		                 knot_strerror(ret));
		return ret;
	}

	/* Update zone version. */
	struct stat st;
	if (stat(zone->conf->file, &st) < 0) {
		log_zone_warning(zone->name, "failed to update zone file (%s)",
		                 knot_strerror(KNOT_EACCES));
		return KNOT_EACCES;
	}

	/* Update zone file serial and journal. */
	zone->zonefile_mtime = st.st_mtime;
	zone->zonefile_serial = serial_to;
	journal_mark_synced(zone->conf->ixfr_db);

	/* Trim extra heap. */
	mem_trim();

	return ret;
}

int zone_update_enqueue(zone_t *zone, knot_pkt_t *pkt, struct process_query_param *param)
{

	/* Create serialized request. */
	struct request_data *req = malloc(sizeof(struct request_data));
	if (req == NULL) {
		return KNOT_ENOMEM;
	}
	memset(req, 0, sizeof(struct request_data));

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
	add_tail(&zone->ddns_queue, (node_t *)req);
	++zone->ddns_queue_size;

	pthread_mutex_unlock(&zone->ddns_lock);

	/* Schedule UPDATE event. */
	zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);

	return KNOT_EOK;
}

size_t zone_update_dequeue(zone_t *zone, list_t *updates)
{
	if (zone == NULL) {
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

bool zone_transfer_needed(const zone_t *zone, const knot_pkt_t *pkt)
{
	if (zone_contents_is_empty(zone->contents)) {
		return true;
	}

	const knot_pktsection_t *answer = knot_pkt_section(pkt, KNOT_ANSWER);
	const knot_rrset_t soa = answer->rr[0];
	if (soa.type != KNOT_RRTYPE_SOA) {
		return false;
	}

	return knot_serial_compare(zone_contents_serial(zone->contents),
	                           knot_soa_serial(&soa.rrs)) < 0;
}
