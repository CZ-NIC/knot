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

#include "contrib/ucw/lists.h"
#include "dnssec/lib/dnssec/kasp.h"
#include "libknot/db/db_lmdb.h"
#include "knot/zone/zone.h"

typedef struct kasp_db kasp_db_t;

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
 * \param dst           output if KNOT_EOK: ptrlist of strings with keys' IDs
 *
 * \return KNOT_E* (KNOT_ENOENT if no keys)
 */
int kasp_db_list_keys(kasp_db_t *db, const knot_dname_t *zone_name, list_t *dst);

/*!
 * \brief For given key ID, gather the info into params structure.
 *
 * \param db            KASP db
 * \param key_id        key ID
 * \param params        output if KNOT_EOK: all key parameters
 *
 * \return KNOT_E*
 */
int kasp_db_key_params(kasp_db_t *db, const char *key_id, key_params_t *params);

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
 * \brief Link an existing key with a zone.
 *
 * The key with this ID must be already present in KASP db.
 *
 * \param db            KASP db
 * \param zone_name     zone to be linked to
 * \param key_id        key ID
 *
 * \return KNOT_E*
 */
int kasp_db_share_key(kasp_db_t *db, const knot_dname_t *zone_name, const char *key_id);

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
                            const dnssec_binary_t *nsec3salt, time_t salt_created);

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
                           dnssec_binary_t *nsec3salt, time_t *salt_created);
