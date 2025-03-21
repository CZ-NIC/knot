/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <histedit.h>

#include "libknot/mm_ctx.h"
#include "contrib/qp-trie/trie.h"

/*! Lookup context. */
typedef struct {
	/*! Memory pool context. */
	knot_mm_t mm;
	/*! Main trie storage. */
	trie_t *trie;

	/*! Current (iteration) data context. */
	struct {
		/*! Stored key. */
		char *key;
		/*! Corresponding key data. */
		void *data;
	} found;

	/*! Iteration context. */
	struct {
		/*! Total number of possibilities. */
		size_t count;
		/*! The first possibility. */
		char *first_key;
		/*! Hat-trie iterator. */
		trie_it_t *it;
	} iter;
} lookup_t;

/*!
 * Initializes the lookup context.
 *
 * \param[in] lookup  Lookup context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int lookup_init(lookup_t *lookup);

/*!
 * Deinitializes the lookup context.
 *
 * \param[in] lookup  Lookup context.
 */
void lookup_deinit(lookup_t *lookup);

/*!
 * Inserts given key and data into the lookup.
 *
 * \param[in] lookup  Lookup context.
 * \param[in] str     Textual key.
 * \param[in] data    Key textual data.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int lookup_insert(lookup_t *lookup, const char *str, void *data);

/*!
 * Removes given key from the lookup.
 *
 * \param[in] lookup  Lookup context.
 * \param[in] str     Textual key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int lookup_remove(lookup_t *lookup, const char *str);

/*!
 * Searches the lookup container for the given key.
 *
 * \note If one candidate, lookup.found contains the key/data,
 *       if more candidates, lookup.found contains the common key prefix and
 *       lookup.iter.first_key is the first candidate key.
 *
 * \param[in] lookup   Lookup context.
 * \param[in] str      Textual key.
 * \param[in] str_len  Textual key length.
 *
 * \return Error code, KNOT_EOK if 1 candidate, KNOT_ENOENT if no candidate,
 *         and KNOT_EFEWDATA if more candidates are possible.
 */
int lookup_search(lookup_t *lookup, const char *str, size_t str_len);

/*!
 * Moves the lookup iterator to the next key candidate.
 *
 * \note lookup.found is updated.
 *
 * \param[in] lookup   Lookup context.
 */
void lookup_list(lookup_t *lookup);

/*!
 * Completes the string based on the lookup content or prints all candidates.
 *
 * \param[in] lookup     Lookup context.
 * \param[in] str        Textual key.
 * \param[in] str_len    Textual key length.
 * \param[in] el         Editline context.
 * \param[in] add_space  Add one space after completed string flag.
 *
 * \return Error code, same as lookup_search().
 */
int lookup_complete(lookup_t *lookup, const char *str, size_t str_len,
                    EditLine *el, bool add_space);
