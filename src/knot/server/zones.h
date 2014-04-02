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
 * \file zones.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * Contains functions for updating zone database from configuration.
 *
 * \addtogroup server
 * @{
 */

#ifndef _KNOTD_ZONES_H_
#define _KNOTD_ZONES_H_

#include <stddef.h>

#include "common/lists.h"
#include "knot/updates/acl.h"
#include "common/evsched.h"
#include "knot/zone/zonedb.h"
#include "knot/conf/conf.h"
#include "knot/server/notify.h"
#include "knot/server/server.h"
#include "knot/server/journal.h"
#include "knot/zone/zone.h"
#include "knot/updates/xfr-in.h"

/* Constants. */
#define ZONES_JITTER_PCT    10 /*!< +-N% jitter to timers. */
#define AXFR_BOOTSTRAP_RETRY (30*1000) /*!< Interval between AXFR BS retries. */
#define AXFR_RETRY_MAXTIME (10*60*1000) /*!< Maximum interval 10mins */

/* Timer special values. */
#define REFRESH_DEFAULT -1 /* Use time value from zone structure. */
#define REFRESH_NOW (knot_random_uint16_t() % 1000) /* Now, but with jitter. */

/*!
 * \brief Decides what type of transfer should be used to update the given zone.
 *.
 * \param zone Zone.
 *
 * \retval
 */
knot_ns_xfr_type_t zones_transfer_to_use(zone_t *zone);

/*!
 * \brief Update zone timers.
 *
 * REFRESH/RETRY/EXPIRE timers are updated according to SOA.
 *
 * \param zone Related zone.
 * \param time Specific timeout or REFRESH_DEFAULT for default.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ERROR
 */
int zones_schedule_refresh(zone_t *zone, int64_t timeout);

/*!
 * \brief Schedule NOTIFY after zone update.
 * \param zone Related zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
int zones_schedule_notify(zone_t *zone, server_t *server);

/*!
 * \brief Cancel DNSSEC event.
 *
 * \param zone  Related zone.
 *
 * \return Error code, KNOT_OK if successful.
 */
int zones_cancel_dnssec(zone_t *zone);

/*!
 * \brief Schedule DNSSEC event.
 * \param zone Related zone.
 * \param unixtime When to schedule.
 * \param force Force sign or not
 *
 * \return Error code, KNOT_OK if successful.
 */
int zones_schedule_dnssec(zone_t *zone, time_t unixtime);


/*! \brief Just sign current zone. */
int zones_dnssec_sign(zone_t *zone, bool force, uint32_t *expires_at);


#endif // _KNOTD_ZONES_H_

/*! @} */
