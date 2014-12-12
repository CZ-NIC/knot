/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file zone.h
 *
 * \brief Zone structure and API for manipulating it.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "common-knot/evsched.h"
#include "common-knot/ref.h"
#include "knot/conf/conf.h"
#include "knot/server/journal.h"
#include "knot/updates/acl.h"
#include "knot/zone/events/events.h"
#include "knot/zone/contents.h"
#include "libknot/dname.h"

struct process_query_param;

/*!
 * \brief Zone flags.
 */
typedef enum zone_flag_t {
	ZONE_FORCE_AXFR   = 1 << 0, /* Force AXFR as next transfer. */
	ZONE_FORCE_RESIGN = 1 << 1  /* Force zone resign. */
} zone_flag_t;

/*!
 * \brief Structure for holding DNS zone.
 */
typedef struct zone_t
{
	knot_dname_t *name;
	zone_contents_t *contents;
	conf_zone_t *conf;
	zone_flag_t flags;

	/*! \brief DDNS queue and lock. */
	pthread_mutex_t ddns_lock;
	size_t ddns_queue_size;
	list_t ddns_queue;
	
	/*! \brief Journal access lock. */
	pthread_mutex_t journal_lock;

	/*! \brief Zone events. */
	zone_events_t events;     /*!< Zone events timers. */
	uint32_t bootstrap_retry; /*!< AXFR/IN bootstrap retry. */
	time_t zonefile_mtime;
	uint32_t zonefile_serial;

} zone_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Creates new zone with emtpy zone content.
 *
 * \param conf  Zone configuration.
 *
 * \return The initialized zone structure or NULL if an error occured.
 */
zone_t *zone_new(conf_zone_t *conf);

/*!
 * \brief Deallocates the zone structure.
 *
 * \note The function also deallocates all bound structures (config, contents, etc.).
 *
 * \param zone Zone to be freed.
 */
void zone_free(zone_t **zone_ptr);

/*!
 * \note Zone change API below, subject to change.
 * \ref #223 New zone API
 * \todo get rid of this
 */
int zone_changes_store(zone_t *zone, list_t *chgs);
int zone_change_store(zone_t *zone, changeset_t *change);
/*!
 * \brief Atomically switch the content of the zone.
 */
zone_contents_t *zone_switch_contents(zone_t *zone,
					   zone_contents_t *new_contents);

/*! \brief Return zone master remote. */
const conf_iface_t *zone_master(const zone_t *zone);

/*! \brief Rotate list of master remotes for current zone. */
void zone_master_rotate(const zone_t *zone);

/*! \brief Synchronize zone file with journal. */
int zone_flush_journal(zone_t *zone);

/*! \brief Enqueue UPDATE request for processing. */
int zone_update_enqueue(zone_t *zone, knot_pkt_t *pkt, struct process_query_param *param);

/*! \brief Dequeue UPDATE request. Returns number of queued updates. */
size_t zone_update_dequeue(zone_t *zone, list_t *updates);

/*! \brief Returns true if final SOA in transfer has newer serial than zone */
bool zone_transfer_needed(const zone_t *zone, const knot_pkt_t *pkt);


/*! @} */
