/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/journal/knot_lmdb.h"
#include "knot/updates/changesets.h"
#include "libknot/dname.h"

typedef struct {
	knot_lmdb_db_t *db;
	const knot_dname_t *zone;
	void *conf; // needed only for journal write operations
} zone_journal_t;

#define JOURNAL_CHUNK_MAX (70 * 1024) // must be at least 64k + 6B
#define JOURNAL_CHUNK_THRESH (15 * 1024)
#define JOURNAL_HEADER_SIZE (32)

/*! \brief Convert journal_mode to LMDB environment flags. */
inline static unsigned journal_env_flags(int journal_mode, bool readonly)
{
	return (journal_mode == JOURNAL_MODE_ASYNC ? (MDB_WRITEMAP | MDB_MAPASYNC) : 0) |
	       (readonly ? MDB_RDONLY : 0);
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
 * \param apex       Zone apex owner name.
 * \param ch_from    Serial "from" of the stored changeset.
 * \param zij        Zone-in-journal is stored.
 * \param chunk_id   Ordinal number of this changeset's chunk.
 *
 * \return DB key. 'mv_data' shall be freed later. 'mv_data' is NULL on failure.
 */
MDB_val journal_make_chunk_key(const knot_dname_t *apex, uint32_t ch_from, bool zij, uint32_t chunk_id);

/*!
 * \brief Check that found LMDB key belongs to a changest chunk of given prefix.
 *
 * \param prefix       Prefix from journal_changeset_id_to_key().
 * \param found_key    Found database record key.
 *
 * \return All OK (hopefully).
 */
bool journal_correct_prefix(MDB_val *prefix, MDB_val *found_key);

/*!
 * \brief Return a key prefix to operate with all zone-related records.
 */
MDB_val journal_zone_prefix(const knot_dname_t *zone);

/*!
 * \brief Delete all zone-related records from journal with open read-write txn.
 */
void journal_del_zone(knot_lmdb_txn_t *txn, const knot_dname_t *zone);

/*!
 * \brief Initialise chunk header.
 *
 * \param chunk   Pointer to the changeset chunk. It must be at least JOURNAL_HEADER_SIZE, perhaps more.
 * \param ch      Serial-to of the changeset being serialized.
 * \param now     Current timestamp.
 */
void journal_make_header(void *chunk, uint32_t ch_serial_to, uint64_t now);

/*!
 * \brief Obtain serial-to of the serialized changeset.
 *
 * \param chunk   Any chunk of a serialized changeset.
 *
 * \return The changeset's serial-to.
 */
uint32_t journal_next_serial(const MDB_val *chunk);

/*!
 * \brief Obtain timestamp of the serialized changeset.
 *
 * \param chunk   Any chunk of a serialized changeset.
 *
 * \return Timestamp in unixtime.
 */
uint64_t journal_ch_timestamp(const MDB_val *chunk);

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
