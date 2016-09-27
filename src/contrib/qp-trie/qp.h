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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libknot/mm_ctx.h"
#include "contrib/hhash.h" /* only for value_t */

/*!
 * \file \brief Native API of QP-tries:
 *
 * - keys are char strings, not necessarily zero-terminated,
 *   the structure copies the contents of the passed keys
 * - values are typedef void* value_t, typically you get an ephemeral pointer to it
 * - key lengths are limited by 2^32-1 ATM
 */

/*! Opaque structure holding a QP-trie. */
struct qp_trie;

/*! Opaque type for holding a QP-trie iterator. */
typedef struct qp_trie_it qp_trie_it_t;

/*! \brief Create a trie instance. */
struct qp_trie* qp_trie_create(knot_mm_t *mm);

/*! \brief Free a trie instance. */
void qp_trie_free(struct qp_trie *tbl);

/*! \brief Clear a trie instance (make it empty). */
void qp_trie_clear(struct qp_trie *tbl);

/*! \brief Return the number of keys in the trie. */
size_t qp_trie_weight(const struct qp_trie *tbl);

/*! \brief Search the trie, returning NULL on failure. */
value_t* qp_trie_get_try(struct qp_trie *tbl, const char *key, uint32_t len);

/*! \brief Search the trie, inserting NULL value_t on failure. */
value_t* qp_trie_get_ins(struct qp_trie *tbl, const char *key, uint32_t len);

/*!
 * \brief Search for less-or-equal element.
 *
 * \param val must be valid; it will be set to NULL if not found or errored.
 * \return 0 for exact match, -1 for previous, 1 for not-found, or KNOT_ENOMEM.
 */
int qp_trie_get_leq(struct qp_trie *tbl, const char *key, uint32_t len, value_t **val);

/*!
 * \brief Apply a function to every value_t, in order.
 *
 * \return KNOT_EOK if success or KNOT_E* if error.
 */
int qp_trie_apply(struct qp_trie *tbl, int (*f)(value_t *, void *), void *d);

/*!
 * \brief Remove an item, returning KNOT_EOK if succeeded or KNOT_ENOENT if not found.
 *
 * If val!=NULL and deletion succeeded, the deleted value is set.
 */
int qp_trie_del(struct qp_trie *tbl, const char *key, uint32_t len, value_t *val);

/*! \brief Create a new iterator pointing to the first element (if any). */
qp_trie_it_t* qp_trie_it_begin(struct qp_trie *tbl);

/*!
 * \brief Advance the iterator to the next element.
 *
 * Iteration is in ascending lexicographical order.
 * In particular, the empty string would be considered as the very first.
 */
void qp_trie_it_next(qp_trie_it_t *it);

/*! \brief Test if the iterator has gone past the last element. */
bool qp_trie_it_finished(qp_trie_it_t *it);

/*! \brief Free any resources of the iterator. It's OK to call it on NULL. */
void qp_trie_it_free(qp_trie_it_t *it);

/*! \brief Return pointer to the key of the current element. */
const char* qp_trie_it_key(qp_trie_it_t *it, uint32_t *len);

/*! \brief Return pointer to the value of the current element (writable). */
value_t* qp_trie_it_val(qp_trie_it_t *it);
