/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief Hopscotch hashing scheme based hash table.
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

struct knot_mm;

/*! \brief Bitvector type. */
typedef unsigned hhbitvec_t;

/*! \brief Element value. */
typedef void* value_t;

/*! \brief Mode flags. */
enum {
	HHASH_INSERT     = 1 << 0, /* Insert if not exists. */
	HHASH_FORCE      = 1 << 1, /* Force vacate a hash bucket. */
	HHASH_LEFT       = 1 << 2, /* Split left side. */
	HHASH_RIGHT      = 1 << 3, /* Split right side. */
	HHASH_CONSUME    = 1 << 4  /* Consume first byte of the split items. */
};

/*! \brief Element descriptor, contains data and bitmap of adjacent items. */
typedef struct hhelem {
	hhbitvec_t hop; /* Hop bitvector. */
	char *d; /* { value_t val, uint16_t keylen, char[] key } */
} hhelem_t;

typedef struct hhash {
	/* Compatibility with HAT-trie nodes. */
	uint8_t flag;
	uint8_t c0;
	uint8_t c1;

	/* Metadata */
	uint32_t size;      /*!< Number of buckets */
	uint32_t weight;    /*!< Table weight (number of inserted). */

	/* Table data storage. */
	struct knot_mm *mm; /*!< Memory manager. */
	uint32_t *index;    /*!< Order index (optional). */
	hhelem_t item[];    /*!< Table items. */
} hhash_t;

/*!
 * \brief Create hopscotch hash table.
 *
 * \param size Fixed size.
 *
 * \return created table
 */
hhash_t *hhash_create(uint32_t size);

/*! \brief Create hopscotch hash table (custom memory manager). */
hhash_t *hhash_create_mm(uint32_t size, const struct knot_mm *mm);

/*!
 * \brief Clear hash table.
 *
 * \param tbl Hash table.
 */
void hhash_clear(hhash_t *tbl);

/*!
 * \brief Free hash table and keys.
 *
 * \param tbl Hash table.
 */
void hhash_free(hhash_t *tbl);

/*!
 * \brief Find key in the hash table and return pointer to it's value.
 *
 * \param tbl Hash table.
 * \param key Key.
 * \param len Key length.
 *
 * \retval pointer to value if found
 * \retval NULL if not exists
 */
value_t *hhash_find(hhash_t* tbl, const char* key, uint16_t len);

/*!
 * \brief Insert/replace value for given key.
 *
 * \param tbl Hash table.
 * \param key Key.
 * \param len Key length.
 * \param val Value.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 */
int hhash_insert(hhash_t* tbl, const char* key, uint16_t len, value_t val);

/*!
 * \brief Return pointer to value for given key (insert if not exists).
 *
 * \note This is more complex function than \fn hhash_insert() which is preferred
 *       for easier usage.
 *
 * \param tbl Hash table.
 * \param key Key.
 * \param len Key length.
 * \param mode Operation mode flags.
 *
 * \retval pointer to new/existing value
 * \retval NULL if the table is full or no memory
 */
value_t *hhash_map(hhash_t* tbl, const char* key, uint16_t len, uint16_t mode);

/*!
 * \brief Remove value from hash table.
 *
 * \param tbl Hash table.
 * \param key Key.
 * \param len Key length.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOENT
 */
int hhash_del(hhash_t* tbl, const char* key, uint16_t len);

/*
 * Hash table allows to build order index for extra memory costs.
 * This is not required, but useful if the table is small and insertions
 * don't happen very often.
 * Keep in mind to rebuild index after the insertions/deletes are complete
 */

/*! \brief Return value from ordered index. */
value_t *hhash_indexval(hhash_t* tbl, unsigned i);

/*! \brief Build index for fast ordered lookup.
 *
 * Nothing is done if the index was OK already;
 * it's automatically invalidated when an operation could damage it.
 * */
void hhash_build_index(hhash_t* tbl);

/*!
 * \brief Find a key that is exact match or lexicographic predecessor.
 *
 * \retval  0 if exact match
 * \retval  1 if couldn't find and no predecessor is found
 * \retval -1 if found predecessor
 */
int hhash_find_leq(hhash_t* tbl, const char* key, uint16_t len, value_t **dst);

/*!
 * \brief Find a key that is a lexicographic successor.
 *
 * \retval  0 if successor found.
 * \retval  1 if couldn't find a successor.
 */
int hhash_find_next(hhash_t* tbl, const char* key, uint16_t len, value_t** dst);

/*! \brief Hash table iterator. */
typedef struct htable_iter {
    unsigned flags; /* Internal */
    hhash_t* tbl;   /* Iterated table. */
    uint32_t i;     /* Current direct/indirect index. */
} hhash_iter_t;

/*! \brief Set iterator the the beginning of the table. */
void hhash_iter_begin (hhash_t*, hhash_iter_t*, bool sorted);

/*! \brief Next value. */
void hhash_iter_next (hhash_iter_t*);

/*! \brief Return true if at the end. */
bool hhash_iter_finished (hhash_iter_t*);

/*! \brief Return current key/keylen. */
const char *hhash_iter_key (hhash_iter_t*, uint16_t* len);

/*! \brief Return current value. */
value_t *hhash_iter_val(hhash_iter_t*);

/*! @} */
