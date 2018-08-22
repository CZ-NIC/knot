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

#include <pthread.h>

#include "libknot/db/db.h"
#include "contrib/ucw/lists.h"
#include "knot/updates/changesets.h"
#include "knot/journal/serialization.h"
#include "knot/journal/chgset_ctx.h"
#include "knot/zone/serial.h"

/*! \brief Minimum journal size. */
#define JOURNAL_MIN_FSLIMIT	(1 * 1024 * 1024)

typedef enum {
	JOURNAL_MODE_ROBUST = 0, // Robust journal DB disk synchronization.
	JOURNAL_MODE_ASYNC  = 1, // Asynchronous journal DB disk synchronization.
} journal_mode_t;

typedef struct {
	knot_db_t *db;
	const knot_db_api_t *db_api;
	char *path;
	size_t fslimit;
	journal_mode_t mode;
	pthread_mutex_t db_mutex; // please delete this once you move DB opening from journal_open to db_init
} journal_db_t;

typedef struct {
	journal_db_t *db;
	knot_dname_t *zone;
} journal_t;

typedef enum {
	JOURNAL_CHECK_SILENT = 0, // No logging, just curious for return value.
	JOURNAL_CHECK_WARN   = 1, // Log journal inconsistencies.
	JOURNAL_CHECK_INFO   = 2, // Log journal state.
	JOURNAL_CHECK_STDERR = 3, // Log everything and redirect to stderr.
} journal_check_level_t;

struct journal_txn;

/*!
 * \brief Initialize shared journal DB file. The DB will be open on first use.
 *
 * \param db             Database to be initialized. Must be (*db == NULL) before!
 * \param lmdb_dir_path  Path to the directory with DB
 * \param lmdb_fslimit   Maximum size of DB data file
 * \param mode           Journal DB synchronization mode.
 *
 * \return KNOT_E*
 */
int journal_db_init(journal_db_t **db, const char *lmdb_dir_path, size_t lmdb_fslimit,
                    journal_mode_t mode);

/*!
 * \brief Close shared journal DB file.
 *
 * \param db DB to close.
 */
void journal_db_close(journal_db_t **db);

/*!
 * \brief List the zones contained in journal DB.
 *
 * \param[in] db      Shared journal DB
 * \param[out] zones  List of strings (char *) of zone names
 *
 * \return KNOT_EOK    ok
 * \retval KNOT_ENOMEM no zones found
 * \retval KNOT_EMALF  different # of zones found than expected
 * \retval KNOT_E*     other error
 */
int journal_db_list_zones(journal_db_t **db, list_t *zones);

/*!
 * \brief Allocate a new journal structure.
 *
 * \retval new journal instance if successful.
 * \retval NULL on error.
 */
journal_t *journal_new(void);

/*!
 * \brief Free a journal structure.
 *
 * \param journal  A journal structure to free.
 */
void journal_free(journal_t **journal);

/*!
 * \brief Open/create the journal based on the filesystem path to LMDB directory
 *
 * \param journal    Journal struct to use.
 * \param db         Shared journal database.
 * \param zone_name  Name of the zone this journal belongs to.
 *
 * \retval KNOT_EOK on success.
 * \return < KNOT_EOK on other errors.
 */
int journal_open(journal_t *journal, journal_db_t **db,
                 const knot_dname_t *zone_name);

/*!
 * \brief Close journal.
 *
 * \param journal  Journal to close.
 */
void journal_close(journal_t *journal);

/*!
 * \brief Load changesets from journal since "from" serial.
 *
 * \param journal  Journal to load from.
 * \param dst      Store changesets here.
 * \param from     Start serial.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOENT when the lookup of the first entry fails.
 * \return < KNOT_EOK on other error.
 */
int journal_load_changesets(journal_t *journal, list_t *dst, uint32_t from);

int journal_load_chgset_ctx(journal_t *j, chgset_ctx_list_t *dst, uint32_t from);

/*!
 * \brief Load changesets from journal, starting with bootstrap changeset.
 *
 * \param journal  Journal to load from.
 * \param dst      Store changesets here, starting with bootstrap changeset.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ENOENT when there is no bootstrap changeset.
 * \return < KNOT_EOK on other error.
 */
int journal_load_bootstrap(journal_t *journal, list_t *dst);

/*!
 * \brief Store changesets in journal.
 *
 * \param journal  Journal to store in.
 * \param src      Changesets to store.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBUSY when full, asking zone to flush itself to zonefile
 *                    to allow cleaning up history and freeing up space
 * \retval KNOT_ESPACE when full and not able to free up any space
 * \return < KNOT_EOK on other errors.
 */
int journal_store_changesets(journal_t *journal, list_t *src);

/*!
 * \brief Store changesets in journal.
 *
 * \param journal  Journal to store in.
 * \param change   Changeset to store.
 *
 * \retval (same as for journal_store_changesets())
 */
int journal_store_changeset(journal_t *journal, changeset_t *change);

/*!
 * \brief Open the journal database.
 *
 * This is an "almost static" function, which is mostly called by other journal
 * methods like journal_open() and journal_exists(). However it can be called
 * separately just for more precise error resolution.
 *
 * \param db Journal to be opened.
 * \return KNOT_E*
 */
int journal_open_db(journal_db_t **db);

/*!
 * \brief Check if this (zone's) journal is present in shared journal DB.
 *
 * \param db         Shared journal DB
 * \param zone_name  Name of the zone of the journal in question
 *
 * \return true or false
 */
bool journal_exists(journal_db_t **db, knot_dname_t *zone_name);

/*! \brief Tell the journal that zone has been flushed.
 *
 * \param journal  Journal to flush.
 *
 * \return KNOT_E*
 */
int journal_flush(journal_t *journal);

/*! \brief Remove completely this (zone's) journal from shared journal DB.
 *
 * This must be called with opened journal.
 *
 * \param journal Journal to be deleted
 *
 * \return KNOT_E*
 */
int journal_scrape(journal_t *journal);

/*! \brief Obtain public information from journal metadata
 */
void journal_metadata_info(journal_t *journal, bool *is_empty, kserial_t *merged_serial,
                           kserial_t *first_serial, kserial_t *last_flushed,
                           kserial_t *serial_to, uint64_t *occupied, uint64_t *occupied_all_zones);

/*! \brief Check the journal consistency, errors to stderr.
 *
 * \param journal     Journal to check.
 * \param warn_level  Journal check level.
 *
 * \return KNOT_E*
 */
int journal_check(journal_t *journal, journal_check_level_t warn_level);

void journal_txn_commit(struct journal_txn *txn);

/*! @} */
