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
#include "common/acl.h"
#include "common/evsched.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/zone/zonedb.h"
#include "knot/conf/conf.h"
#include "knot/server/notify.h"
#include "knot/server/server.h"
#include "knot/server/journal.h"
#include "libknot/zone/zone.h"
#include "libknot/updates/xfr-in.h"

/* Constants. */
#define ZONES_JITTER_PCT    10 /*!< +-N% jitter to timers. */
#define IXFR_DBSYNC_TIMEOUT (60*1000) /*!< Database sync timeout = 60s. */
#define AXFR_BOOTSTRAP_RETRY (30*1000) /*!< Interval between AXFR BS retries. */
#define AXFR_RETRY_MAXTIME (10*60*1000) /*!< Maximum interval 10mins */

enum {
	REFRESH_DEFAULT = -1 /* Use time value from zone structure. */
};

/*!
 * \brief Zone-related data.
 */
typedef struct zonedata_t
{
	/*! \brief Shortcut to zone config entry. */
	conf_zone_t *conf;

	/*! \brief Shortcut to server instance. */
	server_t  *server;

	/*! \brief Zone data lock for exclusive access. */
	pthread_mutex_t lock;

	/*! \brief Access control lists. */
	acl_t *xfr_out;    /*!< ACL for xfr-out.*/
	acl_t *notify_in;  /*!< ACL for notify-in.*/
	acl_t *notify_out; /*!< ACL for notify-out.*/
	acl_t *update_in; /*!< ACL for notify-out.*/

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
	uint32_t zonefile_serial;
} zonedata_t;

/*!
 * \brief Update zone database according to configuration.
 *
 * Creates a new database, copies references those zones from the old database
 * which are still in the configuration, loads any new zones required and
 * replaces the database inside the namserver.
 *
 * It also creates a list of deprecated zones that should be deleted once the
 * function finishes.
 *
 * This function uses RCU mechanism to guard the access to the config and
 * nameserver and to publish the new database in the nameserver.
 *
 * \param[in] conf Configuration.
 * \param[in] ns Nameserver which holds the zone database.
 * \param[out] db_old Old database, containing only zones which should be
 *                    deleted afterwards.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ERROR
 */
int zones_update_db_from_config(const conf_t *conf, knot_nameserver_t *ns,
                               knot_zonedb_t **db_old);

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
int zones_zonefile_sync(knot_zone_t *zone, journal_t *journal);

/*!
 * \todo Document me.
 */
int zones_query_check_zone(const knot_zone_t *zone, uint8_t q_opcode,
                           const sockaddr_t *addr, knot_tsig_key_t **tsig_key,
                           knot_rcode_t *rcode);

/*!
 * \todo Document me.
 */
int zones_xfr_check_zone(knot_ns_xfr_t *xfr, knot_rcode_t *rcode);

/*!
 * \todo Document me.
 */
int zones_normal_query_answer(knot_nameserver_t *nameserver,
                              knot_packet_t *query, const sockaddr_t *addr,
                              uint8_t *response_wire, size_t *rsize,
                              knot_ns_transport_t transport);

/*!
 * \todo Document me.
 */
int zones_process_update(knot_nameserver_t *nameserver,
                         knot_packet_t *query, const sockaddr_t *addr,
                         uint8_t *resp_wire, size_t *rsize,
                         int fd, knot_ns_transport_t transport);

/*!
 * \brief Processes normal response packet.
 *
 * \param nameserver Name server structure to provide the needed data.
 * \param from Address of the response sender.
 * \param packet Parsed response packet.
 * \param response_wire Place for the response in wire format.
 * \param rsize Input: maximum acceptable size of the response. Output: real
 *              size of the response.
 *
 * \retval KNOT_EOK if a valid response was created.
 * \retval KNOT_EINVAL on invalid parameters or packet.
 * \retval KNOT_EMALF if an error occured and the response is not valid.
 */
int zones_process_response(knot_nameserver_t *nameserver,
                           int exp_msgid,
                           sockaddr_t *from,
                           knot_packet_t *packet, uint8_t *response_wire,
                           size_t *rsize);

/*!
 * \brief Decides what type of transfer should be used to update the given zone.
 *.
 * \param data Zone data for associated zone.
 *
 * \retval
 */
knot_ns_xfr_type_t zones_transfer_to_use(zonedata_t *data);

int zones_save_zone(const knot_ns_xfr_t *xfr);

/*!
 * \brief Name server config hook.
 *
 * Routine for dynamic name server reconfiguration.
 *
 * \param conf Current configuration.
 * \param data Instance of the nameserver structure to update.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL
 * \retval KNOT_ERROR
 */
int zones_ns_conf_hook(const struct conf_t *conf, void *data);

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
int zones_store_changesets(knot_zone_t *zone, knot_changesets_t *src, journal_t *j);

/*!
 * \brief Begin changesets storing transaction.
 *
 * \retval pointer to journal if successful
 * \retval NULL on failure.
 */
journal_t *zones_store_changesets_begin(knot_zone_t *zone);

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

/*!
 * \brief Load changesets from journal.
 *
 * Changesets will be stored on a permanent storage.
 * Journal may be compacted, resulting in flattening changeset history.
 *
 * In case of KNOT_ERANGE error, whole zone content should be sent instead,
 * as the changeset history cannot be recovered.
 *
 * \param zone Zone containing a changeset journal.
 * \param dst Container to be loaded.
 * \param from Starting SOA serial (oldest).
 * \param to Ending SOA serial (newest).
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ERANGE when changeset history cannot be reconstructed.
 *
 * \todo Expects the xfr structure to be initialized in some way.
 */
int zones_xfr_load_changesets(knot_ns_xfr_t *xfr, uint32_t serial_from,
                              uint32_t serial_to);

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
int zones_create_changeset(const knot_zone_t *old_zone,
                           const knot_zone_t *new_zone,
                           knot_changeset_t *changeset);

int zones_store_and_apply_chgsets(knot_changesets_t *chs,
                                  knot_zone_t *zone,
                                  knot_zone_contents_t **new_contents,
                                  const char *msgpref, int type);

/*!
 * \brief Update zone timers.
 *
 * REFRESH/RETRY/EXPIRE timers are updated according to SOA.
 *
 * \param zone Related zone.
 * \param time Specific time or REFRESH_DEFAULT for default.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ERROR
 */
int zones_schedule_refresh(knot_zone_t *zone, int64_t time);

/*!
 * \brief Schedule NOTIFY after zone update.
 * \param zone Related zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
int zones_schedule_notify(knot_zone_t *zone);

/*!
 * \brief Schedule DNSSEC event.
 * \param zone Related zone.
 * \param time When to schedule
 * \param force Force sign or not
 *
 * \return Error code, KNOT_OK if successful.
 */
int zones_schedule_dnssec(knot_zone_t *zone, int64_t time, bool force);

/*!
 * \brief Processes forwarded UPDATE response packet.
 * \todo #1291 move to appropriate section (DDNS).
 */
int zones_process_update_response(knot_ns_xfr_t *data, uint8_t *rwire, size_t *rsize);

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
int zones_verify_tsig_query(const knot_packet_t *query,
                            const knot_tsig_key_t *key,
                            knot_rcode_t *rcode, uint16_t *tsig_rcode,
                            uint64_t *tsig_prev_time_signed);

#endif // _KNOTD_ZONES_H_

/*! @} */
