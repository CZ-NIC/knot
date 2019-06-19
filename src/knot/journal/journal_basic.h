/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/conf/schema.h"
#include "knot/journal/knot_lmdb.h"
#include "knot/updates/changesets.h"
#include "libknot/dname.h"

typedef struct {
	knot_lmdb_db_t *db;
	const knot_dname_t *zone;
} zone_journal_t;

#define JOURNAL_CHUNK_MAX (70 * 1024)
#define JOURNAL_HEADER_SIZE (32)

/*! \brief Convert journal_mode to LMDB environment flags. */
inline static unsigned journal_env_flags(int journal_mode)
{
	return journal_mode == JOURNAL_MODE_ASYNC ? (MDB_WRITEMAP | MDB_MAPASYNC) : 0;
}

/*!
 * \brief Create a database key prefix to search for a changeset.
 *
 * \param zone_in_journal   True if searching for zone-in-journal special changeset.
 * \param serial            Serial-from of the changeset to be searched for. Ignored if 'zone_in_journal'.
 * \param zone              Name of the zone.
 *
 * \return DB key. 'mv_data' shall be freed later. 'mv_data' is NULL on failure.
 */
MDB_val journal_changeset_id_to_key(bool zone_in_journal, uint32_t serial, const knot_dname_t *zone);

/*!
 * \brief Create a database key for changeset chunk.
 *
 * \param ch         Corresponding changeset (perhaps to be stored).
 * \param chunk_id   Ordinal number of this changeset's chunk.
 *
 * \return DB key. 'mv_data' shall be freed later. 'mv_data' is NULL on failure.
 */
MDB_val journal_changeset_to_chunk_key(const changeset_t *ch, uint32_t chunk_id);

/*!
 * \brief Initialise chunk header.
 *
 * \param chunk   Pointer to the changeset chunk. It must be at least JOURNAL_HEADER_SIZE, perhaps more.
 * \param ch      Serial-to of the changeset being serialized.
 */
void journal_make_header(void *chunk, uint32_t ch_serial_to);

/*!
 * \brief Obtain serial-to of the serialized changeset.
 *
 * \param chunk   Any chunk of a serialized changeset.
 *
 * \return The changeset's serial-to.
 */
uint32_t journal_next_serial(const MDB_val *chunk);

/*!
 * \brief Obtain serial-to of a changeset stored in journal.
 *
 * \param txn         Journal DB transaction.
 * \param zij         True if changeset in question is zone-in-journal.
 * \param serial      Serial-from of the changeset in question.
 * \param zone        Zone name.
 * \param serial_to   Output: serial-to of the changeset in question.
 *
 * \return True if the changeset exists in the journal.
 */
bool journal_serial_to(knot_lmdb_txn_t *txn, bool zij, uint32_t serial,
                       const knot_dname_t *zone, uint32_t *serial_to);

/*! \brief Return true if the changeset in question exists in the journal. */
inline static bool journal_contains(knot_lmdb_txn_t *txn, bool zone, uint32_t serial, const knot_dname_t *zone_name)
{
	return journal_serial_to(txn, zone, serial, zone_name, NULL);
}

/*! \brief Return true if the journal may be flushed according to conf. */
bool journal_allow_flush(zone_journal_t j);

/*! \brief Return configured maximal per-zone usage of journal DB. */
size_t journal_conf_max_usage(zone_journal_t j);

/*! \brief Return configured maximal depth of journal. */
size_t journal_conf_max_changesets(zone_journal_t j);
