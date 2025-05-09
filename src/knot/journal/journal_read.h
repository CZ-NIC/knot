/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/journal/journal_basic.h"

typedef struct journal_read journal_read_t;

typedef int (*journal_read_cb_t)(bool in_remove_section, const knot_rrset_t *rr, void *ctx);

typedef int (*journal_walk_cb_t)(bool special, const changeset_t *ch, uint64_t timestamp, void *ctx);

/*!
 * \brief Start reading journal from specified changeset.
 *
 * \param j             Journal to be read.
 * \param read_zone     True if reading shall start with zone-in-journal.
 * \param serial_from   Serial-from of the changeset to be started at (ignored if 'read_zone').
 * \param ctx           Output: journal reading context initialised.
 *
 * \return KNOT_E*
 */
int journal_read_begin(zone_journal_t j, bool read_zone, uint32_t serial_from, journal_read_t **ctx);

/*!
 * \brief Read a single RRSet from a journal changeset.
 *
 * \param ctx                    Journal reading context.
 * \param rr                     Output: RRSet to be filled with serialized data.
 * \param allow_next_changeset   True to allow jumping to next changeset.
 *
 * \return False if no more RRSet in this changeset/journal, or failure.
 */
bool journal_read_rrset(journal_read_t *ctx, knot_rrset_t *rr, bool allow_next_changeset);

/*!
 * \brief Free up heap allocations by journal_read_rrset().
 *
 * \param rr   RRSet initialised by journal_read_rrset().
 */
void journal_read_clear_rrset(knot_rrset_t *rr);

// TODO move somewhere. Libknot?
inline static bool rr_is_apex_soa(const knot_rrset_t *rr, const knot_dname_t *apex)
{
	return (rr->type == KNOT_RRTYPE_SOA && knot_dname_is_equal(rr->owner, apex));
}

/*!
 * \brief Read all RRSets up to the end of journal, calling a function for each.
 *
 * \note Closes reading context at the end.
 *
 * \param read   Journal reading context.
 * \param cb     Callback to be called on each read.
 * \param ctx    Arbitrary context to be passed to the callback.
 *
 * \return An error code from either journal operations or from the callback.
 */
int journal_read_rrsets(journal_read_t *read, journal_read_cb_t cb, void *ctx);

/*!
 * \brief Read a single changeset from journal.
 *
 * \param ctx   Journal reading context.
 * \param ch    Output: changeset to be filled with serialized data.
 *
 * \return False if no more changesets in the journal, or failure.
 */
bool journal_read_changeset(journal_read_t *ctx, changeset_t *ch);

/*!
 * \brief Free up heap allocations by journal_read_changeset().
 *
 * \param ch   Changeset initialised by journal_read_changeset().
 */
void journal_read_clear_changeset(changeset_t *ch);

/*!
 * \brief Obtain error code from the journal_read operations previously performed.
 *
 * \param ctx             Journal reading context.
 * \param another_error   An error code from outside the reading operations to be combined.
 *
 * \return KNOT_EOK if completely every operation succeeded, KNOT_E*
 */
int journal_read_get_error(const journal_read_t *ctx, int another_error);

/*!
 * \brief Finalise journal reading.
 *
 * \param ctx   Journal reading context (will be freed).
 */
void journal_read_end(journal_read_t *ctx);

/*!
 * \brief Call a function for each changeset in journal.
 *
 * This is a variant of journal_walk() see below.
 * The difference is that iteration starts at specified serial.
 * Similarly to how IXFR works.
 * The callback is called for each found changeset, or just once
 * with ch=NULL if none is found.
 *
 * \param j      Zone journal to be read.
 * \param from   SOA serial to start at.
 * \param cb     Callback to be called for each changeset (or its non-existence).
 * \param ctx    Arbitrary context to be passed to the callback.
 *
 * \return An error code from either journal operations or from the callback.
 * \retval KNOT_ENOENT if the journal is not empty, but the requested serial not present.
 */
int journal_walk_from(zone_journal_t j, uint32_t from,
                      journal_walk_cb_t cb, void *ctx);

/*!
 * \brief Call a function for each changeset stored in journal.
 *
 * First, the callback will be called for the special changeset -
 * either zone-in-journal or merged changeset, with special=true.
 * If there is no such, it will be called anyway with ch=NULL.
 *
 * Than, the callback will be called for each regular changeset
 * with special=false. If there is none, it will be called once
 * with ch=NULL.
 *
 * \param j     Zone journal to be read.
 * \param cb    Callback to be called for each changeset (or its non-existence).
 * \param ctx   Arbitrary context to be passed to the callback.
 *
 * \return An error code from either journal operations or from the callback.
 */
int journal_walk(zone_journal_t j, journal_walk_cb_t cb, void *ctx);

/*!
 * \brief Perform semantic check of the zone journal (consistency, metadata...).
 *
 * \param j   Zone journal to be checked.
 *
 * \retval KNOT_E* ( < 0 ) if an error during journal operation.
 * \retval > 100 if some inconsistency found.
 * \return KNOT_EOK of all ok.
 */
int journal_sem_check(zone_journal_t j);
