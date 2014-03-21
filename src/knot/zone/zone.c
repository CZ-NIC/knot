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
#include "common/lists.h"
#include "knot/server/zones.h"
#include "knot/zone/node.h"
#include "knot/zone/zone.h"
#include "knot/zone/contents.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/dnssec/random.h"
#include "libknot/rdata.h"
#include "libknot/util/utils.h"

/*!
 * \brief Called when the reference count for zone drops to zero.
  */
static void knot_zone_dtor(struct ref_t *p) {
	zone_t *z = (zone_t *)p;
	zone_free(&z);
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
	conf_remote_t *r = 0;
	WALK_LIST(r, *acl_list) {
		conf_iface_t *cfg_if = r->remote;
		acl_insert(new_acl, &cfg_if->addr, cfg_if->prefix, cfg_if->key);
	}

	*acl = new_acl;

	return KNOT_EOK;
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
	set_acl(&zone->xfr_out,    &conf->acl.xfr_out);
	set_acl(&zone->notify_in,  &conf->acl.notify_in);
	set_acl(&zone->update_in,  &conf->acl.update_in);

	// Initialize XFR database
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

void zone_free(zone_t **zone_ptr)
{
	if (zone_ptr == NULL || *zone_ptr == NULL) {
		return;
	}

	zone_t *zone = *zone_ptr;

	knot_dname_free(&zone->name);

	// TODO: review
//	evsched_cancel(zone->next_event);
//	evsched_event_free(zone->next_event);

	acl_delete(&zone->xfr_out);
	acl_delete(&zone->notify_in);
	acl_delete(&zone->update_in);
	pthread_mutex_destroy(&zone->lock);
	pthread_mutex_destroy(&zone->ddns_lock);

	/* Close IXFR db. */
	journal_close(zone->ixfr_db);

	/* Free assigned config. */
	conf_free_zone(zone->conf);

	/* Free zone contents. */
	zone_contents_deep_free(&zone->contents);

	free(zone);
	*zone_ptr = NULL;
}

zone_contents_t *zone_switch_contents(zone_t *zone,
					   zone_contents_t *new_contents)
{
	if (zone == NULL) {
		return NULL;
	}

	zone_contents_t *old_contents;
	old_contents = rcu_xchg_pointer(&zone->contents, new_contents);

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
