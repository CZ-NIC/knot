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
#include <urcu.h>

#include "dnssec/random.h"
#include "libknot/descriptor.h"
#include "knot/common/evsched.h"
#include "libknot/internal/lists.h"
#include "knot/common/log.h"
#include "knot/common/trim.h"
#include "knot/zone/node.h"
#include "knot/zone/serial.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/contents.h"
#include "knot/updates/apply.h"
#include "libknot/processing/requestor.h"
#include "knot/nameserver/process_query.h"
#include "libknot/libknot.h"
#include "libknot/dname.h"
#include "libknot/internal/utils.h"
#include "libknot/internal/mem.h"
#include "libknot/rrtype/soa.h"

#define JOURNAL_SUFFIX	".diff.db"

static void free_ddns_queue(zone_t *z)
{
	struct knot_request *n = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, z->ddns_queue) {
		close(n->fd);
		knot_pkt_free(&n->query);
		rem_node((node_t *)n);
		free(n);
	}
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

	/* Free zone contents. */
	zone_contents_deep_free(&zone->contents);

	if (zone->query_plan != NULL) {
		conf_deactivate_modules(conf(), &zone->query_modules,
		                        zone->query_plan);
	}

	free(zone);
	*zone_ptr = NULL;
}

int zone_change_store(zone_t *zone, changeset_t *change)
{
	assert(zone);
	assert(change);

	conf_val_t val = conf_zone_get(conf(), C_IXFR_FSLIMIT, zone->name);
	int64_t ixfr_fslimit = conf_int(&val);
	char *journal_file = conf_journalfile(conf(), zone->name);

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_store_changeset(change, journal_file, ixfr_fslimit);
	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal is full, flushing");

		/* Transaction rolled back, journal released, we may flush. */
		ret = zone_flush_journal(zone);
		if (ret == KNOT_EOK) {
			ret = journal_store_changeset(change, journal_file, ixfr_fslimit);
		}
	}
	pthread_mutex_unlock(&zone->journal_lock);

	free(journal_file);

	return ret;
}

int zone_changes_store(zone_t *zone, list_t *chgs)
{
	assert(zone);
	assert(chgs);

	conf_val_t val = conf_zone_get(conf(), C_IXFR_FSLIMIT, zone->name);
	int64_t ixfr_fslimit = conf_int(&val);
	char *journal_file = conf_journalfile(conf(), zone->name);

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_store_changesets(chgs, journal_file, ixfr_fslimit);
	if (ret == KNOT_EBUSY) {
		log_zone_notice(zone->name, "journal is full, flushing");

		/* Transaction rolled back, journal released, we may flush. */
		ret = zone_flush_journal(zone);
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

bool zone_is_master(const zone_t *zone)
{
	conf_val_t val = conf_zone_get(conf(), C_MASTER, zone->name);
	return conf_val_count(&val) > 0 ? false : true;
}

conf_remote_t zone_master(const zone_t *zone)
{
	conf_val_t val = conf_zone_get(conf(), C_MASTER, zone->name);

	/* Seek the current master if possible. */
	if (zone->master_index < conf_val_count(&val)) {
		for (size_t index = 0; index < zone->master_index; index++) {
			conf_val_next(&val);
		}
	}

	return conf_remote(conf(), &val);
}

void zone_master_rotate(zone_t *zone)
{
	conf_val_t val = conf_zone_get(conf(), C_MASTER, zone->name);

	if (zone->master_index + 2 <= conf_val_count(&val)) {
		zone->master_index += 1;
	} else {
		zone->master_index = 0;
	}
}

int zone_flush_journal(zone_t *zone)
{
	/*! @note Function expects nobody will change zone contents meanwile. */

	if (zone == NULL || zone_contents_is_empty(zone->contents)) {
		return KNOT_EINVAL;
	}

	/* Check for difference against zonefile serial. */
	zone_contents_t *contents = zone->contents;
	uint32_t serial_to = zone_contents_serial(contents);
	if (zone->zonefile_serial == serial_to) {
		return KNOT_EOK; /* No differences. */
	}

	/* Fetch zone source (where it came from). */
	const struct sockaddr_storage *from = NULL;
	if (!zone_is_master(zone)) {
		const conf_remote_t master = zone_master(zone);
		from = &master.addr;
	}

	char *zonefile = conf_zonefile(conf(), zone->name);

	/* Synchronize journal. */
	int ret = zonefile_write(zonefile, contents, from);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone file updated, serial %u -> %u",
		              zone->zonefile_serial, serial_to);
	} else {
		log_zone_warning(zone->name, "failed to update zone file (%s)",
		                 knot_strerror(ret));
		free(zonefile);
		return ret;
	}

	/* Update zone version. */
	struct stat st;
	if (stat(zonefile, &st) < 0) {
		log_zone_warning(zone->name, "failed to update zone file (%s)",
		                 knot_strerror(KNOT_EACCES));
		free(zonefile);
		return KNOT_EACCES;
	}

	free(zonefile);

	char *journal_file = conf_journalfile(conf(), zone->name);

	/* Update zone file serial and journal. */
	zone->zonefile_mtime = st.st_mtime;
	zone->zonefile_serial = serial_to;
	journal_mark_synced(journal_file);

	free(journal_file);

	/* Trim extra heap. */
	mem_trim();

	return ret;
}

int zone_update_enqueue(zone_t *zone, knot_pkt_t *pkt, struct process_query_param *param)
{

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
	if (answer->count < 1) {
		return false;
	}

	const knot_rrset_t *soa = knot_pkt_rr(answer, 0);
	if (soa->type != KNOT_RRTYPE_SOA) {
		return false;
	}

	return serial_compare(zone_contents_serial(zone->contents),
	                           knot_soa_serial(&soa->rrs)) < 0;
}
