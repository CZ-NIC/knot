/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/libknot.h"
#include "contrib/ucw/lists.h"
#include "knot/updates/changesets.h"
#include "knot/journal/serialization.h"

/*!
 * \brief j->fslimit special value to open with minimal possible mapsize
 *
 * ...it is equal to the actual DB file size.
 * Beware of using this value for the first time initialized DB !
 * It is mostly useful for read only access
 */
#define KNOT_JOURNAL_FSLIMIT_SAMEASLAST (400 * 1024)

typedef struct {
	knot_db_t *db;
	const knot_db_api_t *db_api;
	char *path;
	size_t fslimit;
	pthread_mutex_t db_mutex; // please delete this once you move DB opening from journal_open to db_init
	// common metadata: last_inserter_zone, last_total_occupied, journal_count
} journal_db_t;

typedef struct {
	uint32_t first_serial;		// serial_from of the first changeset
	uint32_t last_serial;		// serial_from of the last changeset
	uint32_t last_serial_to;	// serial_to of the last changeset
	uint32_t last_flushed;		// serial_from of the last flushed (or merged) chengeset
	uint32_t merged_serial;		// "serial_from" of merged changeset
	uint32_t dirty_serial;		// serial_from of an incompletely inserted changeset which shall be deleted (see DB_MAX_INSERT_TXN)
	uint32_t changeset_count;	// # of changesets in this journal
	uint32_t flags;			// LAST_FLUSHED_VALID, SERIAL_TO_VALID, MERGED_SERIAL_VALID
	// specific metadata: occupied
} journal_metadata_t;

typedef struct {
	journal_db_t *db;
	knot_dname_t *zone;
	//journal_metadata_t md;
} journal_t;

enum {
	KNOT_JOURNAL_CHECK_SILENT = 0,
	KNOT_JOURNAL_CHECK_WARN = 1,
	KNOT_JOURNAL_CHECK_INFO = 2
};

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
 * \brief Open journal.
 *
 * \param j          Journal struct to use.
 * \param db         Shared journal database
 * \param zone_name  Name of the zone this journal belongs to.
 *
 * \retval KNOT_EOK on success.
 * \return < KNOT_EOK on other errors.
 */
int journal_open(journal_t *j, journal_db_t **db, const knot_dname_t *zone_name);

/*!
 * \brief Close journal.
 *
 * \param journal  Journal to close.
 */
void journal_close(journal_t *journal);

/*!
 * \brief Initialize shared journal DB file. The DB will be open on first use.
 *
 * \param db            Database to be initialized. Must be (*db == NULL) before!
 * \param lmdb_dir_path Path to the directory with DB
 * \param lmdb_fslimit  Maximum size of DB data file
 *
 * \return KNOT_E*
 */
int init_journal_db(journal_db_t **db, const char *lmdb_dir_path, size_t lmdb_fslimit);

/*!
 * \brief Close shared journal DB file.
 *
 * \param db DB to close.
 */
void close_journal_db(journal_db_t **db);

/*!
 * \brief Load changesets from journal.
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
 * \brief Check if this (zone's) journal is present in shared journal DB.
 *
 * \param db        Shared journal DB
 * \param zone_name Name of the zone of the journal in question
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
 * \param j Journal to be deleted
 *
 * \return KNOT_E*
 */
int scrape_journal(journal_t *j);

/*! \brief Obtain public information from journal metadata
 *
 * \param[in]  j           Journal
 * \param[out] is_empty    1 if j contains no changesets
 * \param[out] serial_from [if !is_empty] starting serial of changesets history
 * \param[out] serial_to   [if !is_empty] ending serial of changesets history
 */
void journal_metadata_info(journal_t *j, int *is_empty, uint32_t *serial_from, uint32_t *serial_to);

/*!
 * \brief List the zones contained in journal DB.
 *
 * \param db[in]        Shared journal DB
 * \param zones[out]    List of strings (char *) of zone names
 *
 * \return KNOT_EOK    ok
 * \retval KNOT_ENOMEM no zones found
 * \retval KNOT_EMALF  different # of zones found than expected
 * \retval KNOT_E*     other error
 */
int journal_db_list_zones(journal_db_t **db, list_t *zones);

/*! \brief Check the journal consistency, errors to stderr.
 *
 * \param journal  Journal to check.
 * \param warn_level SILENT: no logging, just curious for return value; WARN: log journal inconsistencies; INFO: log journal state
 *
 * \return KNOT_E*
 */
int journal_check(journal_t *j, int warn_level);

/*! @} */
