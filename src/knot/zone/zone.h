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

#include "common/evsched.h"
#include "common/ref.h"
#include "libknot/dname.h"
#include "knot/conf/conf.h"
#include "knot/server/journal.h"
#include "knot/updates/acl.h"
#include "knot/zone/zone-contents.h"

/*!
 * \brief Zone flags.
 */
typedef enum zone_flag_t {
	ZONE_DISCARDED = 1 << 1  /*! Zone waiting to be discarded. */
} zone_flag_t;

struct server_t;

/*!
 * \brief Structure for holding DNS zone.
 */
typedef struct zone_t {

	//! \todo Move ACLs into configuration.
	//! \todo Remove refcounting + flags.
	//! \todo Remove server_t.
	//! \todo Remove zonefile_{serial,mtime}, use zone-dirty flag instead

	ref_t ref;     /*!< Reference counting. */
	knot_dname_t *name;

	knot_zone_contents_t *contents;

	zone_flag_t flags;

	/*! \brief Zone file flushing. */
	time_t zonefile_mtime;
	uint32_t zonefile_serial;

	/*! \brief Shortcut to zone config entry. */
	conf_zone_t *conf;

	/*! \brief Zone data lock for exclusive access. */
	pthread_mutex_t lock;
	/*! \brief Zone lock for DDNS. */
	pthread_mutex_t ddns_lock;

	/*! \brief Access control lists. */
	acl_t *xfr_out;    /*!< ACL for outgoing transfers.*/
	acl_t *notify_in;  /*!< ACL for incoming notifications.*/
	acl_t *update_in;  /*!< ACL for incoming updates.*/

	/*! \brief XFR-IN scheduler. */
	struct {
		event_t *timer;           /*!< Timer for REFRESH/RETRY. */
		event_t *expire;          /*!< Timer for EXPIRE. */
		uint32_t bootstrap_retry; /*!< AXFR/IN bootstrap retry. */
		unsigned state;
	} xfr_in;

	struct {
		event_t *timer;  /*!< Timer for DNSSEC events. */
		uint32_t   refresh_at;  /*!< Next refresh time. */
	} dnssec;

	/*! \brief Zone IXFR history. */
	journal_t *ixfr_db;
	event_t *ixfr_dbsync;   /*!< Syncing IXFR db to zonefile. */
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

/*! \brief Increase zone reference count. */
static inline void zone_retain(zone_t *zone)
{
	ref_retain(&zone->ref);
}

/*! \brief Decrease zone reference count. */
static inline void zone_release(zone_t *zone)
{
	ref_release(&zone->ref);
}

/*!
 * \brief Atomically switch the content of the zone.
 */
knot_zone_contents_t *zone_switch_contents(zone_t *zone,
					   knot_zone_contents_t *new_contents);

/*!
 * \brief Initialize zone timers.
 *
 * \todo Zone timers should be in a separate file, callbacks are still scattered.
 */
int zone_timers_create(zone_t *zone, evsched_t *sched);

/*!
 * \brief Freeze the zone timers.
 */
int zone_timers_freeze(zone_t *zone);

/*!
 * \brief Reschedule frozen zone timers.
 */
int zone_timers_thaw(zone_t *zone);

/*!
 * \brief Return zone master interface.
 */
const conf_iface_t *zone_master(const zone_t *zone);

/*! @} */
