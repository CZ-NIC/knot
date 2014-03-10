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
#define AXFR_BOOTSTRAP_RETRY (30*1000) /*!< Jitter cap between AXFR bootstrap retries. */
#define AXFR_RETRY_MAXTIME (24*60*60*1000) /*!< Maximum AXFR retry interval cap of 24 hours. */

/* Timer special values. */
#define REFRESH_DEFAULT -1 /* Use time value from zone structure. */
#define REFRESH_NOW (knot_random_uint16_t() % 1000) /* Now, but with jitter. */

/*!
 * \brief Sync zone data back to text zonefile.
 *
 * In case when SOA serial of the zonefile differs from the SOA serial of the
 * loaded zone, zonefile needs to be updated.
 *
 * \note Current implementation rewrites the zone file.
 *
 * \param zone Evaluated zone.
 * \param journal Journal to sync.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_ERANGE if zonefile is in sync with journal.
 * \retval KNOT_EINVAL on invalid parameter.
 * \retval KNOT_ERROR on unspecified error during processing.
 */
int zones_zonefile_sync(zone_t *zone, journal_t *journal);

/*!
 * \brief Processes normal response packet.
 *
 * \param server Name server structure to provide the needed data.
 * \param packet Parsed response packet.
 *
 * \retval KNOT_EOK if a valid response was created.
 * \retval KNOT_EINVAL on invalid parameters or packet.
 * \retval KNOT_EMALF if an error occured and the response is not valid.
 */
int zones_process_response(server_t *server,
                           int exp_msgid,
                           struct sockaddr_storage *from,
                           knot_pkt_t *packet);

/*!
 * \brief Decides what type of transfer should be used to update the given zone.
 *.
 * \param zone Zone.
 *
 * \retval
 */
knot_ns_xfr_type_t zones_transfer_to_use(zone_t *zone);

int zones_save_zone(const knot_ns_xfr_t *xfr);

/*!
 * \brief Store changesets in journal.
 *
 * Changesets will be stored to a permanent storage.
 * Journal may be compacted, resulting in flattening changeset history.
 *
 * \param zone Zone associated with the changeset.
 * \param src Changesets.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_EAGAIN if journal needs to be synced with zonefile first.
 *
 * \todo Expects the xfr structure to be initialized in some way.
 * \todo Update documentation!!!
 */
int zones_store_changesets(zone_t *zone, knot_changesets_t *src, journal_t *j);

/*!
 * \brief Begin changesets storing transaction.
 *
 * \retval pointer to journal if successful
 * \retval NULL on failure.
 */
journal_t *zones_store_changesets_begin(zone_t *zone);

/*!
 * \brief Commit stored changesets.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOENT when no transaction is pending.
 */
int zones_store_changesets_commit(journal_t *j);

/*!
 * \brief Rollback stored changesets.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOENT when no transaction is pending.
 */
int zones_store_changesets_rollback(journal_t *j);

/*! \todo Document me. */
int zones_changesets_from_binary(knot_changesets_t *chgsets);

/*! \todo Document me. */
int zones_changesets_to_binary(knot_changesets_t *chgsets);

int zones_load_changesets(const zone_t *zone,
			  knot_changesets_t *dst,
			  uint32_t from, uint32_t to) __attribute__((deprecated));

/*!
 * \brief Creates changesets from zones difference.
 *
 * Also saves changesets to journal, which is taken from old zone.
 *
 * \param old_zone Old zone, previously served by server.
 * \param new_zone New zone, to be served by server, after creating changesets.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid arguments.
 * \retval KNOT_ERANGE when new serial is lower than the old one.
 * \retval KNOT_ENODIFF when new zone's serial are equal.
 * \retval KNOT_ERROR when there was error creating changesets.
 */
int zones_create_changeset(const zone_t *old_zone,
                           const zone_t *new_zone,
                           knot_changeset_t *changeset);

int zones_store_and_apply_chgsets(knot_changesets_t *chs,
                                  zone_t *zone,
                                  knot_zone_contents_t **new_contents,
                                  const char *msgpref, int type);

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

/*!
 * \brief Schedule IXFR sync for given zone.
 *
 * \param zone     Zone to scheduler IXFR sync for.
 * \param timeout  Sync time in seconds.
 */
void zones_schedule_zonefile_sync(zone_t *zone, uint32_t timeout);

/*!
 * \brief Verify TSIG in query.
 *
 * \param query Query packet.
 * \param key TSIG key used for this query.
 * \param rcode Dst for resulting RCODE.
 * \param tsig_rcode Dst for resulting TSIG RCODE.
 * \param tsig_prev_time_signed Dst for previout time signed.
 *
 * \return KNOT_EOK if verified or error if not.
 */
int zones_verify_tsig_query(const knot_pkt_t *query,
                            const knot_tsig_key_t *key,
                            knot_rcode_t *rcode, uint16_t *tsig_rcode,
                            uint64_t *tsig_prev_time_signed);

/*!
 * \brief Apply changesets to zone from journal.
 *
 * \param zone Specified zone.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOENT if zone has no contents.
 * \retval KNOT_ERROR on unspecified error.
 */
int zones_journal_apply(zone_t *zone);

/*!
 * \brief Creates diff and DNSSEC changesets and stores them to journal.
 *
 * \param z             Zone configuration.
 * \param zone          Zone to sign.
 * \param old_zone      Previous zone.
 * \param zone_changed  Set to true if the zone was loaded or modified.
 *
 * \return Error code, KNOT_OK if successful.
 */
int zones_do_diff_and_sign(zone_t *zone, zone_t *old_zone, bool zone_changed);

/*! \brief Just sign current zone. */
int zones_dnssec_sign(zone_t *zone, bool force, uint32_t *expires_at);

/*
 * Event callbacks.
 */

int zones_expire_ev(event_t *event);
int zones_refresh_ev(event_t *event);
int zones_flush_ev(event_t *event);
int zones_dnssec_ev(event_t *event);

/*! \note Exported API for UPDATE processing, but this should really be done
 *        in a better way as it's very similar code to ixfr-from-diff signing code. */
bool zones_dnskey_changed(const knot_zone_contents_t *old_contents,
                          const knot_zone_contents_t *new_contents);
bool zones_nsec3param_changed(const knot_zone_contents_t *old_contents,
                              const knot_zone_contents_t *new_contents);
int zones_merge_and_store_changesets(zone_t *zone,
                                     knot_changesets_t *diff_chs,
                                     knot_changesets_t *sec_chs,
                                     journal_t **transaction);
void zones_free_merged_changesets(knot_changesets_t *diff_chs,
                                  knot_changesets_t *sec_chs);
uint32_t zones_next_serial(zone_t *zone);


#endif // _KNOTD_ZONES_H_

/*! @} */
