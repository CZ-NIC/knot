/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <time.h>

#include "contrib/time.h"
#include "contrib/ucw/lists.h"
#include "libknot/db/db_lmdb.h"
#include "libknot/dname.h"
#include "knot/dnssec/kasp/policy.h"

typedef struct kasp_db kasp_db_t;

typedef enum { // the enum values MUST match those from keyclass_t !!
        KASPDB_SERIAL_MASTER = 0x5,
        KASPDB_SERIAL_LASTSIGNED = 0x6,
} kaspdb_serial_t;

/*!
 * \brief Returns kasp_db_t singleton, to be used for signing all zones.
 *
 * De/initialized with server_t, used in zone contents signing context.
 */
kasp_db_t **kaspdb(void);

/*!
 * \brief Initialize kasp_db_t, prepare to simple open on-demand.
 *
 * \param db            structure to initialize
 * \param path          path to the LMDB directory (will be created)
 * \param mapsize       LMDB map size
 *
 * \return KNOT_E*
 */
int kasp_db_init(kasp_db_t **db, const char *path, size_t mapsize);

/*!
 * \brief Re-initialize kasp_db_t if not already open.
 *
 * \param db            structure to initialize
 * \param new_path      new path to LMDB
 * \param new_mapsize   new LMDB map size
 *
 * \retval KNOT_EBUSY   can't reconfigure DB path because already open
 * \retval KNOT_EEXIST  can't reconfigure mapsize because already open
 * \retval KNOT_ENODIFF already open, but no change needed => OK
 * \retval KNOT_EINVAL, KNOT_ENOMEM, etc. standard errors
 * \return KNOT_EOK     reconfigured successfully
 */
int kasp_db_reconfigure(kasp_db_t **db, const char *new_path, size_t new_mapsize);

/*!
 * \brief Determine if kasp_db possibly exists at all.
 *
 * This is useful to avoid creating kasp_db by opening it just to check if anything is there.
 */
bool kasp_db_exists(kasp_db_t *db);

/*!
 * \brief Perform real ctreate/open of KASP db.
 */
int kasp_db_open(kasp_db_t *db);

/*!
 * \brief Close KASP db if open and free the structure.
 */
void kasp_db_close(kasp_db_t **db);

/*!
 * \brief For given zone, list all keys (their IDs) belonging to it.
 *
 * \param db            KASP db
 * \param zone_name     name of the zone in question
 * \param dst           output if KNOT_EOK: ptrlist of keys' params
 *
 * \return KNOT_E* (KNOT_ENOENT if no keys)
 */
int kasp_db_list_keys(kasp_db_t *db, const knot_dname_t *zone_name, list_t *dst);

/*!
 * \brief Remove a key from zone. Delete the key if no zone has it anymore.
 *
 * \param db            KASP db
 * \param zone_name     zone to be removed from
 * \param key_id        ID of key to be removed
 * \param still_used    output if KNOT_EOK: is the key still in use by other zones?
 *
 * \return KNOT_E*
 */
int kasp_db_delete_key(kasp_db_t *db, const knot_dname_t *zone_name, const char *key_id, bool *still_used);

/*!
 * \brief Remove all zone's keys from DB, including nsec3param
 * \param db            KASP db
 * \param zone_name     zoen to be removed
 *
 * \return KNOT_E*
 */
int kasp_db_delete_all(kasp_db_t *db, const knot_dname_t *zone_name);

/*!
 * \brief Add a key to the DB (possibly overwrite) and link it to a zone.
 *
 * Stores new key with given params into KASP db. If a key with the same ID had been present
 * in KASP db already, its params get silently overwritten by those new params.
 * Moreover, the key ID is linked to the zone.
 *
 * \param db            KASP db
 * \param zone_name     name of the zone the new key shall belong to
 * \param params        key params, incl. ID
 *
 * \return KNOT_E*
 */
int kasp_db_add_key(kasp_db_t *db, const knot_dname_t *zone_name, const key_params_t *params);

/*!
 * \brief Link a key from another zone.
 *
 * \param db            KASP db
 * \param zone_from     name of the zone the key belongs to
 * \param zone_to       name of the zone the key shall belong to as well
 * \param key_id        ID of the key in question
 *
 * \return KNOT_E*
 */
int kasp_db_share_key(kasp_db_t *db, const knot_dname_t *zone_from, const knot_dname_t *zone_to, const char *key_id);

/*!
 * \brief Store NSEC3 salt for given zone (possibly overwrites old salt).
 *
 * \param db            KASP db
 * \param zone_name     zone name
 * \param nsec3salt     new NSEC3 salt
 * \param salt_created  timestamp when the salt was created
 *
 * \return KNOT_E*
 */
int kasp_db_store_nsec3salt(kasp_db_t *db, const knot_dname_t *zone_name,
                            const dnssec_binary_t *nsec3salt, knot_time_t salt_created);

/*!
 * \brief Load NSEC3 salt for given zone.
 *
 * \param db            KASP db
 * \param zone_name     zone name
 * \param nsec3salt     output if KNOT_EOK: the zone's NSEC3 salt
 * \param salt_created  output if KNOT_EOK: timestamp when the salt was created
 *
 * \return KNOT_E* (KNOT_ENOENT if not stored before)
 */
int kasp_db_load_nsec3salt(kasp_db_t *db, const knot_dname_t *zone_name,
                           dnssec_binary_t *nsec3salt, knot_time_t *salt_created);

/*!
 * \brief Store SOA serial number of master or last signed serial.
 *
 * \param db             KASP db
 * \param zone_name      zone name
 * \param serial_type    kind of serial to be stored
 * \param serial         new serial to be stored
 *
 * \return KNOT_E*
 */
int kasp_db_store_serial(kasp_db_t *db, const knot_dname_t *zone_name,
                         kaspdb_serial_t serial_type, uint32_t serial);

/*!
 * \brief Load saved SOA serial number of master or last signed serial.
 *
 * \param db             KASP db
 * \param zone_name      zone name
 * \param serial_type    kind of serial to be loaded
 * \param serial         output if KNOT_EOK: desired serial number
 *
 * \return KNOT_E* (KNOT_ENOENT if not stored before)
 */
int kasp_db_load_serial(kasp_db_t *db, const knot_dname_t *zone_name,
                        kaspdb_serial_t serial_type, uint32_t *serial);

/*!
 * \brief For given policy name, obtain last generated key.
 *
 * \param db            KASP db
 * \param policy_string a name identifying the signing policy with shared keys
 * \param lp_zone       out: the zone owning the last generated key
 * \param lp_keyid      out: the ID of the last generated key
 *
 * \return KNOT_E*
 */
int kasp_db_get_policy_last(kasp_db_t *db, const char *policy_string, knot_dname_t **lp_zone,
			    char **lp_keyid);

/*!
 * \brief For given policy name, try to reset last generated key.
 *
 * \param db            KASP db
 * \param policy_string a name identifying the signing policy with shared keys
 * \param last_lp_keyid just for check: ID of the key the caller thinks is the policy-last
 * \param new_lp_zone   zone name of the new policy-last key
 * \param new_lp_keyid  ID of the new policy-last key
 *
 * \retval KNOT_ESEMCHECK       lasp_lp_keyid does not correspond to real last key. Probably another zone
 *                              changed policy-last key in the meantime. Re-run kasp_db_get_policy_last()
 * \retval KNOT_EOK             policy-last key set up successfully to given zone/ID
 * \return KNOT_E*              common error
 */
int kasp_db_set_policy_last(kasp_db_t *db, const char *policy_string, const char *last_lp_keyid,
			    const knot_dname_t *new_lp_zone, const char *new_lp_keyid);

/*!
 * \brief List all zones that have anything stored in KASP db.
 *
 * It's quite slow, but we expect KASP db not to be so large.
 *
 * \param db   KASP db
 * \param dst  List of zone names
 *
 * \return KNOT_E*
 */
int kasp_db_list_zones(kasp_db_t *db, list_t *dst);
