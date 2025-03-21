/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Zone database represents a list of managed zones.
 */

#pragma once

#include "knot/zone/zone.h"
#include "libknot/dname.h"
#include "contrib/qp-trie/trie.h"

struct knot_zonedb {
	trie_t *trie;
	knot_mm_t mm;
};

/*
 * Mapping of iterators to internal data structure.
 */
typedef trie_it_t knot_zonedb_iter_t;
#define knot_zonedb_iter_begin(db) trie_it_begin((db)->trie)
#define knot_zonedb_iter_finished(it) trie_it_finished(it)
#define knot_zonedb_iter_next(it) trie_it_next(it)
#define knot_zonedb_iter_free(it) trie_it_free(it)
#define knot_zonedb_iter_val(it) *trie_it_val(it)

/*
 * Simple foreach() access with callback and variable number of callback params.
 */
#define knot_zonedb_foreach(db, callback, ...) \
{ \
	knot_zonedb_iter_t *it = knot_zonedb_iter_begin((db)); \
	while(!knot_zonedb_iter_finished(it)) { \
		callback((zone_t *)knot_zonedb_iter_val(it), ##__VA_ARGS__); \
		knot_zonedb_iter_next(it); \
	} \
	knot_zonedb_iter_free(it); \
}

/*!
 * \brief Allocates and initializes the zone database structure.
 *
 * \return Pointer to the created zone database structure or NULL if an error
 *         occurred.
 */
knot_zonedb_t *knot_zonedb_new(void);

/*!
 * \brief Adds new zone to the database.
 *
 * \param db Zone database to store the zone.
 * \param zone Parsed zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EZONEIN
 */
int knot_zonedb_insert(knot_zonedb_t *db, zone_t *zone);

/*!
 * \brief Removes the given zone from the database if it exists.
 *
 * \param db Zone database to remove from.
 * \param zone_name Name of the zone to be removed.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOZONE
 */
int knot_zonedb_del(knot_zonedb_t *db, const knot_dname_t *zone_name);

/*!
 * \brief Finds zone exactly matching the given zone name.
 *
 * \param db Zone database to search in.
 * \param zone_name Domain name representing the zone name.
 *
 * \return Zone with \a zone_name being the owner of the zone apex or NULL if
 *         not found.
 */
zone_t *knot_zonedb_find(knot_zonedb_t *db, const knot_dname_t *zone_name);

/*!
 * \brief Finds pointer to zone exactly matching the given zone name.
 *
 * \param db          Zone database to search in.
 * \param zone_name   Domain name representing the zone name.
 *
 * \return Pointer in zoneDB pointing at the zone structure, or NULL.
 */
zone_t **knot_zonedb_find_ptr(knot_zonedb_t *db, const knot_dname_t *zone_name);

/*!
 * \brief Finds zone the given domain name should belong to.
 *
 * \param db Zone database to search in.
 * \param zone_name Domain name to find zone for.
 *
 * \retval Zone in which the domain name should be present or NULL if no such
 *         zone is found.
 */
zone_t *knot_zonedb_find_suffix(knot_zonedb_t *db, const knot_dname_t *zone_name);

size_t knot_zonedb_size(const knot_zonedb_t *db);

/*!
 * \brief Destroys and deallocates the zone database structure (but not the
 *        zones within).
 *
 * \param db Zone database to be destroyed.
 */
void knot_zonedb_free(knot_zonedb_t **db);

/*!
 * \brief Destroys and deallocates the whole zone database including the zones.
 *
 * \param db Zone database to be destroyed.
 * \param abort_txn Indication that possible zone transactions are aborted.
 */
void knot_zonedb_deep_free(knot_zonedb_t **db, bool abort_txn);
