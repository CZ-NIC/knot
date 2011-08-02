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

#ifndef _KNOT_ZONES_H_
#define _KNOT_ZONES_H_

#include "common/lists.h"
#include "common/acl.h"
#include "knot/server/name-server.h"
#include "dnslib/zonedb.h"
#include "knot/conf/conf.h"
#include "knot/server/journal.h"
#include "dnslib/zone.h"
#include "knot/server/xfr-in.h"

/* Constants. */
#define IXFR_DBSYNC_TIMEOUT (60*1000) /*!< Database sync timeout = 60s. */

/*!
 * \brief Zone-related data.
 */
typedef struct zonedata_t
{
	/*! \brief Shortcut to zone config entry. */
	conf_zone_t *conf;

	/*! \brief Zone data lock for exclusive access. */
	pthread_mutex_t lock;

	/*! \brief Access control lists. */
	acl_t *xfr_out;    /*!< ACL for xfr-out.*/
	acl_t *notify_in;  /*!< ACL for notify-in.*/
	acl_t *notify_out; /*!< ACL for notify-out.*/

	/*! \brief XFR-IN scheduler. */
	struct {
		list          **ifaces; /*!< List of availabel interfaces. */
		acl_t         *acl;     /*!< ACL for xfr-in.*/
		sockaddr_t     master;  /*!< Master server for xfr-in.*/
		struct event_t *timer;  /*!< Timer for REFRESH/RETRY. */
		struct event_t *expire; /*!< Timer for REFRESH. */
		int next_id;            /*!< ID of the next awaited SOA resp.*/
	} xfr_in;

	/*! \brief List of pending NOTIFY events. */
	list notify_pending;

	/*! \brief Zone IXFR history. */
	journal_t *ixfr_db;
	struct event_t *ixfr_dbsync;   /*!< Syncing IXFR db to zonefile. */
	uint32_t zonefile_serial;
} zonedata_t;

/*! \todo Document me. */
typedef enum xfr_type_t {
	XFR_TYPE_AIN,  /*!< AXFR-IN request (start transfer). */
	XFR_TYPE_AOUT, /*!< AXFR-OUT request (incoming transfer). */
	XFR_TYPE_IIN,  /*!< IXFR-IN request (start transfer). */
	XFR_TYPE_IOUT  /*!< IXFR-OUT request (incoming transfer). */
} xfr_type_t;

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
int zones_update_db_from_config(const conf_t *conf, dnslib_nameserver_t *ns,
                               dnslib_zonedb_t **db_old);

/*!
 * \brief Sync zone data back to text zonefile.
 *
 * In case when SOA serial of the zonefile differs from the SOA serial of the
 * loaded zone, zonefile needs to be updated.
 *
 * \note Current implementation rewrites the zone file.
 *
 * \param zone Evaluated zone.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL on invalid parameter.
 * \retval KNOT_ERROR on unspecified error during processing.
 */
int zones_zonefile_sync(dnslib_zone_t *zone);

int zones_xfr_check_zone(dnslib_ns_xfr_t *xfr, dnslib_rcode_t *rcode);

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
int zones_process_response(dnslib_nameserver_t *nameserver, 
                           sockaddr_t *from,
                           dnslib_packet_t *packet, uint8_t *response_wire,
                           size_t *rsize);

/*!
 * \brief Decides what type of transfer should be used to update the given zone.
 *
 * \param nameserver Name server structure that uses the zone.
 * \param zone Zone to be updated by the transfer.
 *
 * \retval
 */
xfr_type_t zones_transfer_to_use(const dnslib_zone_contents_t *zone);

int zones_save_zone(const dnslib_ns_xfr_t *xfr);

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
 * Changesets will be stored on a permanent storage.
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
 */
int zones_store_changesets(dnslib_ns_xfr_t *xfr);

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
int zones_xfr_load_changesets(dnslib_ns_xfr_t *xfr);

/*!
 * \brief Apply changesets to zone.
 *
 * Applies a list of XFR-style changesets to the given zone. Also checks if the
 * changesets are applicable (i.e. zone is right and has the right serial).
 *
 * \param zone Zone to which the changesets should be applied.
 * \param chsets Changesets to be applied to the zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int zones_apply_changesets(dnslib_ns_xfr_t *xfr);

#endif // _KNOT_ZONES_H_

/*! @} */
