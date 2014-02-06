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
	ZONE_SLAVE     = 0 << 0, /*! Slave zone */
	ZONE_MASTER    = 1 << 0, /*! Master zone. */
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
	acl_t *xfr_out;    /*!< ACL for xfr-out.*/
	acl_t *notify_in;  /*!< ACL for notify-in.*/
	acl_t *notify_out; /*!< ACL for notify-out.*/
	acl_t *update_in;  /*!< ACL for notify-out.*/

	/*! \brief XFR-IN scheduler. */
	struct {
		acl_t          *acl;      /*!< ACL for xfr-in.*/
		sockaddr_t      master;   /*!< Master server for xfr-in.*/
		sockaddr_t      via;      /*!< Master server transit interface.*/
		knot_tsig_key_t tsig_key; /*!< Master TSIG key. */
		struct event_t *timer;    /*!< Timer for REFRESH/RETRY. */
		struct event_t *expire;   /*!< Timer for REFRESH. */
		uint32_t bootstrap_retry; /*!< AXFR/IN bootstrap retry. */
		int has_master;           /*!< True if it has master set. */
		unsigned state;
	} xfr_in;

	struct event_t *dnssec_timer;  /*!< Timer for DNSSEC events. */

	/*! \brief Zone IXFR history. */
	journal_t *ixfr_db;
	struct event_t *ixfr_dbsync;   /*!< Syncing IXFR db to zonefile. */
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
 * \brief Create zone contents.
 *
 * \param zone  Zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int zone_create_contents(zone_t *zone);

/*!
 * \brief Deallocates the zone structure, without freeing its content.
 *
 * \param zone Zone to be freed.
 */
void zone_free(zone_t **zone_ptr);

/*!
 * \brief Deallocates the zone structure, including the content.
 *
 * \param zone Zone to be freed.
 */
void zone_deep_free(zone_t **zone_ptr);

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
 * \brief Check if the zone is a master zone.
 */
static inline bool zone_is_master(const zone_t *zone)
{
	return zone->flags & ZONE_MASTER;
}

/*!
 * \brief Atomically switch the content of the zone.
 */
knot_zone_contents_t *zone_switch_contents(zone_t *zone,
					   knot_zone_contents_t *new_contents);

/*! @} */
