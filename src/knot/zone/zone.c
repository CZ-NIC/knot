/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "common/descriptor.h"
#include "common/evsched.h"
#include "knot/server/zones.h"
#include "knot/zone/node.h"
#include "knot/zone/zone.h"
#include "knot/zone/zone-contents.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/dnssec/random.h"
#include "libknot/rdata.h"
#include "libknot/util/utils.h"

static const size_t XFRIN_BOOTSTRAP_DELAY = 2000; /*!< AXFR bootstrap avg. delay */

/*!
 * \brief Called when the reference count for zone drops to zero.
  */
static void knot_zone_dtor(struct ref_t *p) {
	zone_t *z = (zone_t *)p;
	zone_deep_free(&z);
}

/*!
 * \brief Set ACL list from configuration.
 *
 * \param acl      ACL to be created.
 * \param acl_list List of remotes from configuration.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOMEM on failed memory allocation.
 */
static int set_acl(acl_t **acl, list_t* acl_list)
{
	assert(acl);
	assert(acl_list);

	/* Create new ACL. */
	acl_t *new_acl = acl_new();
	if (new_acl == NULL) {
		return KNOT_ENOMEM;
	}

	/* Load ACL rules. */
	sockaddr_t addr;
	conf_remote_t *r = 0;
	WALK_LIST(r, *acl_list) {
		/* Initialize address. */
		/*! Port matching disabled, port = 0. */
		sockaddr_init(&addr, -1);
		conf_iface_t *cfg_if = r->remote;
		int ret = sockaddr_set(&addr, cfg_if->family, cfg_if->address, 0);
		sockaddr_setprefix(&addr, cfg_if->prefix);

		/* Load rule. */
		if (ret > 0) {
			acl_insert(new_acl, &addr, cfg_if->key);
		}
	}

	*acl = new_acl;

	return KNOT_EOK;
}

/*!
 * \brief Set XFR-IN parameters.
 * \param zone
 */
static void set_xfrin_parameters(zone_t *zone, conf_zone_t *conf)
{
	assert(zone);
	assert(conf);

	zone->xfr_in.bootstrap_retry = knot_random_uint32_t() % XFRIN_BOOTSTRAP_DELAY;
	zone->xfr_in.has_master = 1;

	conf_remote_t *master = HEAD(conf->acl.xfr_in);
	conf_iface_t *master_if = master->remote;
	sockaddr_set(&zone->xfr_in.master, master_if->family,
		     master_if->address, master_if->port);

	if (sockaddr_isvalid(&master_if->via)) {
		sockaddr_copy(&zone->xfr_in.via, &master_if->via);
	}

	if (master_if->key) {
		memcpy(&zone->xfr_in.tsig_key, master_if->key,
		       sizeof(knot_tsig_key_t));
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

	zone->name = knot_dname_from_str(conf->name);
	knot_dname_to_lower(zone->name);
	if (zone->name == NULL) {
		free(zone);
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ref_init(&zone->ref, knot_zone_dtor);
	zone_retain(zone);

	// Configuration
	zone->conf = conf;

	// Mutexes
	pthread_mutex_init(&zone->lock, 0);
	pthread_mutex_init(&zone->ddns_lock, 0);

	// ACLs
	set_acl(&zone->xfr_in.acl, &conf->acl.xfr_in);
	set_acl(&zone->xfr_out,    &conf->acl.xfr_out);
	set_acl(&zone->notify_in,  &conf->acl.notify_in);
	set_acl(&zone->notify_out, &conf->acl.notify_out);
	set_acl(&zone->update_in,  &conf->acl.update_in);

	// XFR-IN
	if (!EMPTY_LIST(conf->acl.xfr_in)) {
		set_xfrin_parameters(zone, conf);
	}

	/* Initialize IXFR database. */
	zone->ixfr_db = journal_open(conf->ixfr_db, conf->ixfr_fslimit, JOURNAL_DIRTY);
	if (zone->ixfr_db == NULL) {
		char ebuf[256] = {0};
		if (strerror_r(errno, ebuf, sizeof(ebuf)) == 0) {
			log_zone_warning("Couldn't open journal file for "
			                 "zone '%s', disabling incoming "
			                 "IXFR. (%s)\n", conf->name, ebuf);
		}
	}

	return zone;
}

int zone_create_contents(zone_t *zone)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

	knot_node_t *apex = knot_node_new(zone->name, NULL, 0);
	if (!apex) {
		return KNOT_ENOMEM;
	}

	knot_zone_contents_t *contents = knot_zone_contents_new(apex, zone);
	if (!contents) {
		knot_node_free(&apex);
		return KNOT_ENOMEM;
	}

	zone->contents = contents;
	return KNOT_EOK;
}

/*! \brief Cancel and free zone event. */
static void zone_event_free(event_t **event)
{
	if (event == NULL || *event == NULL) {
		return;
	}

	evsched_t *sched = (*event)->parent;
	assert(sched);
	evsched_cancel(sched, *event);
	evsched_event_free(sched, *event);
	*event = NULL;
}

void zone_free(zone_t **zone_ptr)
{
	if (zone_ptr == NULL || *zone_ptr == NULL) {
		return;
	}

	zone_t *zone = *zone_ptr;

	knot_dname_free(&zone->name);

	/* Cancel and free timers. */
	zone_event_free(&zone->xfr_in.timer);
	zone_event_free(&zone->xfr_in.expire);
	zone_event_free(&zone->ixfr_dbsync);
	zone_event_free(&zone->dnssec_timer);

	acl_delete(&zone->xfr_in.acl);
	acl_delete(&zone->xfr_out);
	acl_delete(&zone->notify_in);
	acl_delete(&zone->notify_out);
	acl_delete(&zone->update_in);
	pthread_mutex_destroy(&zone->lock);
	pthread_mutex_destroy(&zone->ddns_lock);

	/* Close IXFR db. */
	journal_close(zone->ixfr_db);

	/* Free assigned config. */
	conf_free_zone(zone->conf);

	free(zone);
	*zone_ptr = NULL;
}

void zone_deep_free(zone_t **zone_ptr)
{
	if (zone_ptr == NULL || *zone_ptr == NULL) {
		return;
	}

	zone_t *zone = *zone_ptr;

	knot_zone_contents_deep_free(&zone->contents);
	zone_free(zone_ptr);
}

knot_zone_contents_t *zone_switch_contents(zone_t *zone,
					   knot_zone_contents_t *new_contents)
{
	if (zone == NULL) {
		return NULL;
	}

	knot_zone_contents_t *old_contents;
	old_contents = rcu_xchg_pointer(&zone->contents, new_contents);

	return old_contents;
}
