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
#include "knot/server/name-server.h"
#include "dnslib/zonedb.h"
#include "knot/conf/conf.h"

/*!
 * \brief Load zone to zone database.
 *
 * \param zonedb Zone database to load the zone into.
 * \param zone_name Zone name (owner of the apex node).
 * \param filename Path to requested compiled zone file.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_EZONEINVAL
 */
int zones_load_zone(dnslib_zonedb_t *zonedb, const char *zone_name,
                    const char *filename);

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
int zones_update_db_from_config(const conf_t *conf, ns_nameserver_t *ns,
                               dnslib_zonedb_t **db_old);

#endif // _KNOT_ZONES_H_

/*! @} */
