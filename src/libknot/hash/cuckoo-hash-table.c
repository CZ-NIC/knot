/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     /* defines uint32_t etc */
#include <assert.h>
#include <pthread.h>
#include <math.h>

#include <urcu.h>

#include "util/utils.h"
#include "common.h"
#include "util/debug.h"
#include "hash/cuckoo-hash-table.h"
#include "hash/hash-functions.h"
#include "common/dynamic-array.h"

/*----------------------------------------------------------------------------*/
/* Macros and inline functions                                                */
/*----------------------------------------------------------------------------*/

/*!
 * \brief Default size table holding information about used hash table cells
 *        when hashing.
 */
#define RELOCATIONS_DEFAULT 200

/*!
 * \brief Maximum size table holding information about used hash table cells
 *        when hashing (just for debug issues).
 */
#define RELOCATIONS_MAX 1000

/*!
 * \brief Macro for hashing the given key using the universal system.
 *
 * \param system Universal system to use for the hashing.
 * \param key Key to hash.
 * \param length Size of the key in bytes.
 * \param exp Exponent of the hash table size (the size is a power of 2).
 * \param table Hash table index.
 * \param gen Universal system generation.
 *
 * \return Hashed key.
 */
#define HASH(system, key, length, exp, gen, table) \
	us_hash(system, fnv_32_buf(key, length, FNV1_32_INIT), exp, table, gen)

/*!
 * \brief Approximate ratio of hash table size to number of hashed items when 2
 *        tables are used.
 */
static const float SIZE_RATIO_2 = 2;

/*!
 * \brief Approximate ratio of hash table size to number of hashed items when 3
 *        tables are used.
 */
static const float SIZE_RATIO_3 = 1.15;

/*!
 * \brief Approximate ratio of hash table size to number of hashed items when 4
 *        tables are used.
 */
static const float SIZE_RATIO_4 = 1.08;

/*----------------------------------------------------------------------------*/

/*! \brief Flag marking the generation of hash table or its item to be 1. */
static const uint8_t FLAG_GENERATION1     = 0x1; // 00000001
/*! \brief Flag marking the generation of hash table or its item to be 2. */
static const uint8_t FLAG_GENERATION2     = 0x2; // 00000010
/*! \brief Flag marking both generations. */
static const uint8_t FLAG_GENERATION_BOTH = 0x3; // 00000011

/*! \brief Flag used to mark the table when it's being rehashed. */
static const uint8_t FLAG_REHASH          = 0x4; // 00000100

/*----------------------------------------------------------------------------*/
/*! \brief Clears the table / item flags. */
static inline void CLEAR_FLAGS(uint8_t *flags)
{
	*flags = (uint8_t)0x0;
}

/*! \brief Returns the generation stored in the flags. */
static inline uint8_t GET_GENERATION(uint8_t flags)
{
	return (flags & FLAG_GENERATION_BOTH);
}

/*! \brief Checks if the generation stored in both flags are the same. */
static inline int EQUAL_GENERATIONS(uint8_t flags1, uint8_t flags2)
{
	return (GET_GENERATION(flags1) == GET_GENERATION(flags2));
}

/*! \brief Checks if the generation stored in the flags is 1. */
static inline int IS_GENERATION1(uint8_t flags)
{
	return ((flags & FLAG_GENERATION1) != 0);
}

/*! \brief Sets the generation stored in the flags to 1. */
static inline void SET_GENERATION1(uint8_t *flags)
{
	*flags = ((*flags) & ~FLAG_GENERATION2) | FLAG_GENERATION1;
}

/*! \brief Checks if the generation stored in the flags is 2. */
static inline int IS_GENERATION2(uint8_t flags)
{
	return ((flags & FLAG_GENERATION2) != 0);
}

/*! \brief Sets the generation stored in the flags to 2. */
static inline void SET_GENERATION2(uint8_t *flags)
{
	*flags = ((*flags) & ~FLAG_GENERATION1) | FLAG_GENERATION2;
}

/*! \brief Sets the generation stored in the flags to the given generation. */
static inline void SET_GENERATION(uint8_t *flags, uint8_t generation)
{
	*flags = ((*flags) & ~FLAG_GENERATION_BOTH) | generation;
}

/*! \brief Sets the generation stored in the flags to the next one (cyclic). */
static inline uint8_t SET_NEXT_GENERATION(uint8_t *flags)
{
	return ((*flags) ^= FLAG_GENERATION_BOTH);
}

/*! \brief Returns the next generation to the one stored in flags (cyclic). */
static inline uint8_t NEXT_GENERATION(uint8_t flags)
{
	return ((flags & FLAG_GENERATION_BOTH) ^ FLAG_GENERATION_BOTH);
}

/*! \brief Sets the rehashing flag to the flags. */
static inline void SET_REHASHING_ON(uint8_t *flags)
{
	*flags = (*flags | FLAG_REHASH);
}

/*! \brief Removes the rehashing flag from the flags. */
static inline void SET_REHASHING_OFF(uint8_t *flags)
{
	*flags = (*flags & ~FLAG_REHASH);
}

/*! \brief Checks if the rehashing flag is set in the flags. */
static inline int IS_REHASHING(uint8_t flags)
{
	return ((flags & FLAG_REHASH) != 0);
}

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the exponent of the nearest larger power of two.
 */
static uint get_larger_exp(uint n)
{
	uint res = 0;
	while (hashsize(++res) < n) {}

	return res;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Counts the ideal table count and the exponent of those tables' sizes.
 *
 * Only 3 or 4 hash tables are considered. The setup in which less items are
 * wasted is recommended.
 *
 * \param items Number of items to hash.
 * \param table_count Recommended number of tables will be saved here.
 *
 * \return Exponent of the tables' sizes.
 */
static uint get_table_exp_and_count(uint items, uint *table_count)
{
	// considering only 3 or 4 tables
	int exp3 = get_larger_exp((items * SIZE_RATIO_3) / 3);
	int exp4 = get_larger_exp(items * SIZE_RATIO_4) - 2;
	
	if (exp4 < 0) {
		exp4 = 1;
	}

	dbg_ck("Determining ideal table size...\n");
	dbg_ck("\tNumber of items: %u\n", items);
	dbg_ck("\tThree tables: size of one table: %u, total size: %u\n",
	         hashsize(exp3), 3 * hashsize(exp3));
	dbg_ck("\tFour tables: size of one table: %u, total size: %u\n",
	         hashsize(exp4), 4 * hashsize(exp4));

	// we need exponent at least 1 (this is quite ugly..)
	if (exp3 == 0) {
		exp3 = 1;
	}
	if (exp4 == 0) {
		exp4 = 1;
	}
	
	if (exp3 >= 32 || exp4 >= 32) {
		return 0;
	}
	
	if (((hashsize(exp3) * 3) - (items)) < ((hashsize(exp4) * 4) - items)) {
		*table_count = 3;
		return exp3;
	} else {
		*table_count = 4;
		return exp4;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Counts the maximum effective item count based on size of the tables.
 *
 * For 3 tables, the effective utilization should be around 91%.
 * For 4 tables it is 97%.
 *
 * See Fotakis, Dimitris, et al. - Space Efficient Hash Tables with Worst Case
 * Constant Access Time. CiteSeerX. 2003
 * http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.14.5337
 */
static uint get_max_table_items(uint table_count, int table_exponent)
{
	assert(table_count == 3 || table_count == 4);
	
	float coef;
	
	if (table_count == 3) {
		coef = 0.91;
	} else {
		coef = 0.97;
	}
	
	return (uint)floor((table_count * hashsize(table_exponent)) * coef);
}

/*----------------------------------------------------------------------------*/

static int ck_is_full(const ck_hash_table_t *table)
{
	return (table->items >= get_max_table_items(table->table_count, 
	                                            table->table_size_exp));
}

/*----------------------------------------------------------------------------*/

static int ck_stash_is_full(const ck_hash_table_t *table)
{
	return (table->items_in_stash >= STASH_SIZE_MAX);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Clears the given item by assigning a NULL pointer to it.
 */
static inline void ck_clear_item(ck_hash_table_item_t **item)
{
	*item = NULL;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Insert given contents to the hash table item.
 */
static void ck_fill_item(const char *key, size_t key_length, void *value,
                         uint generation, ck_hash_table_item_t *item)
{
	// must allocate new space for key and value, otherwise it will be lost!
	item->key = key;
	item->key_length = key_length;
	item->value = value;
	CLEAR_FLAGS(&item->timestamp);
	item->timestamp = generation;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Swaps two hash table items.
 */
static inline void ck_swap_items(ck_hash_table_item_t **item1,
                                 ck_hash_table_item_t **item2)
{
	ck_hash_table_item_t *tmp = *item1;
	*item1 = *item2;
	*item2 = tmp;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the \a item pointer to the \a to pointer.
 */
static inline void ck_put_item(ck_hash_table_item_t **to,
                               ck_hash_table_item_t *item)
{
	*to = item;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if the hash was already used twice.
 *
 * If yes, it means we entered a loop in the hashing process, so we must stop.
 * Otherwise it remembers that we used the hash.
 *
 * \note According to Kirsch, et al. a check that at most one hash was used
 *       twice should be sufficient. We will retain our version for now.
 *
 * \param used Array of used table indices (hashes).
 * \param hash Hash to check.
 *
 * \retval -1 if the hash was already used twice.
 * \retval -2 if an error occured.
 * \retval 0 if the hash was not used twice yet.
 */
static uint ck_check_used_twice(da_array_t *used, uint32_t hash)
{
	uint i = 0, found = 0;
	while (i <= da_get_count(used) && found < 2) {
		++i;
		if (((uint *)(da_get_items(used)))[i] == hash) {
			++found;
		}
	}

	if (i <= da_get_count(used) && found == 2) {
		dbg_ck_hash("Hashing entered infinite loop.\n");
		return -1;
	} else {
		if (da_reserve(used, 1) < 0) {
			ERR_ALLOC_FAILED;
			return -2;
		}
		((uint *)da_get_items(used))[da_get_count(used)] = hash;
		da_occupy(used, 1);
		assert(da_get_count(used) < RELOCATIONS_MAX);
		return 0;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Compares the key of item with the given key.
 *
 * \param item Item to compare with.
 * \param key Key to compare.
 * \param length Size of the key in bytes.
 *
 * \return <> 0 if the keys match.
 * \return 0 if they don't.
 */
static inline uint ck_items_match(const ck_hash_table_item_t *item,
                                  const char *key, size_t length)
{
	assert(item != NULL);

	return (length == item->key_length
	        && (strncmp(item->key, key, length) == 0));
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Switches the given table number to a randomly chosen other table
 *        number.
 */
static inline void ck_next_table(uint *table, uint table_count)
{
	uint next;
	while ((*table) == (next = knot_quick_rand() % table_count)) {}
	*table = next;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to find the given key in the hash table's stash.
 *
 * \param table Hash table to search in.
 * \param key Key to find.
 * \param length Size of the key in bytes.
 *
 * \return Hash table item matching the key or NULL if not found in the stash.
 */
static ck_hash_table_item_t **ck_find_in_stash(const ck_hash_table_t *table,
                                               const char *key, uint length)
{
	ck_stash_item_t *item = table->stash;
	while (item != NULL) {
		dbg_ck("Comparing item in stash (key: %.*s (size %zu))"
		         "with searched item (key %.*s (size %u)).\n",
		         (int)item->item->key_length, item->item->key,
		         item->item->key_length, (int)length, key, length);
		/*! \todo Can the item be NULL?
		 *        Sometimes it crashed on assert in ck_items_match(),
		 *        But I'm not sure if this may happen or if the
		 *        semantics of the stash are that all items must be
		 *        non-NULL.
		 */
		if (item->item && ck_items_match(item->item, key, length)) {
			return &item->item;
		}
		item = item->next;
	}

	return NULL;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to find item with given key using hash functions from the given
 *        generation.
 *
 * \param table Hash table to search in.
 * \param key Key to find.
 * \param length Size of the key in bytes.
 * \param generation Generation of items (table) to use. Items having other
 *                   generation are ignored.
 */
static ck_hash_table_item_t **ck_find_gen(const ck_hash_table_t *table,
                                          const char *key,
                                          size_t length, uint8_t generation)
{
	uint32_t hash;
	dbg_ck("Finding item in generation: %u\n", generation);

	// check hash tables
	for (uint t = 0; t < table->table_count; ++t) {
		hash = HASH(&table->hash_system, key, length,
		            table->table_size_exp, generation, t);

		dbg_ck("Hash: %u, key: %.*s\n", hash, (int)length, key);
		dbg_ck("Table %d, hash: %u, item: %p\n", t + 1, hash,
		         table->tables[t][hash]);
		if (table->tables[t][hash] != NULL) {
			dbg_ck("Table %u, key: %.*s, value: %p, key "
			         "length: %zu\n",
			         t + 1, (int)table->tables[t][hash]->key_length,
			         table->tables[t][hash]->key,
			         table->tables[t][hash]->value,
			         table->tables[t][hash]->key_length);
		}

		if (table->tables[t][hash] &&
		    ck_items_match(table->tables[t][hash], key, length)) {
			// found
			return &table->tables[t][hash];
		}
	}

	// try to find in stash
	dbg_ck("Searching in stash...\n");

	ck_hash_table_item_t **found =
	        ck_find_in_stash(table, key, length);

	dbg_ck("Found pointer: %p\n", found);
	if (found != NULL) {
		dbg_ck("Stash, key: %.*s, value: %p, key length: %zu\n",
		         (int)(*found)->key_length, (*found)->key,
	                 (*found)->value, (*found)->key_length);
	}

	// ck_find_in_buffer returns NULL if not found, otherwise pointer to
	// item
	return found;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Finds item with given key and returns non-constant pointer to pointer
 *        to the appropriate hash table item.
 *
 * \param table Hash table to search in.
 * \param key Key to find.
 * \param length Size of the key in bytes.
 */
static ck_hash_table_item_t **ck_find_item_nc(const ck_hash_table_t *table,
                                              const char *key, size_t length)
{
	// get the generation of the table so that we use the same value
	uint8_t generation = table->generation;

	// find item using the table generation's hash functions
	ck_hash_table_item_t **found = ck_find_gen(table, key, length,
	                                           GET_GENERATION(generation));
	// if rehashing is in progress, try the next generation's functions
	if (!found && IS_REHASHING(generation)) {
		found = ck_find_gen(table, key, length,
		                    NEXT_GENERATION(generation));
	}

	return found;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Hashes the given item using the given generation.
 *
 * \param table Hash table where to put the item.
 * \param to_hash In: Item to hash. Out: NULL if successful, item that failed
 *                to hash if not.
 * \param free Free place where to put the last moved item when the hasing
 *             is unsuccessful.
 * \param generation Generation of items (table) to be used for hashing.
 *
 * \retval 0 if successful and no loop occured.
 * \retval 1 if a loop occured and the item was inserted to the \a free place.
 */
static int ck_hash_item(ck_hash_table_t *table, ck_hash_table_item_t **to_hash,
                        ck_hash_table_item_t **free, uint8_t generation)
{
	da_array_t used[table->table_count];
	for (uint i = 0; i < table->table_count; ++i) {
		da_initialize(&used[i], RELOCATIONS_DEFAULT, sizeof(uint));
	}

	// hash until empty cell is encountered or until loop appears

	dbg_ck_hash("Hashing key: %.*s of size %zu.\n",
	              (int)(*to_hash)->key_length, (*to_hash)->key,
	              (*to_hash)->key_length);

	uint next_table = 0;

	uint32_t hash = HASH(&table->hash_system, (*to_hash)->key,
	                     (*to_hash)->key_length, table->table_size_exp,
	                     generation, next_table);

	dbg_ck_hash("New hash: %u.\n", hash);
	assert(hash < hashsize(table->table_size_exp));

	((uint *)da_get_items(&used[next_table]))
	[da_get_count(&used[next_table])] = hash;
	ck_hash_table_item_t **next = &table->tables[next_table][hash];
	dbg_ck_hash("Item to be moved: %p, place in table: %p\n",
	              *next, next);
	ck_hash_table_item_t **moving = to_hash;

	int loop = 0;

	while (*next != NULL) {
		dbg_ck_hash("Swapping items to hash: %p and Moving: %p\n",
		              to_hash, moving);
		ck_swap_items(to_hash, moving); // first time it's unnecessary

		// set the generation of the inserted item to the next
		SET_GENERATION(&(*moving)->timestamp, generation);

		moving = next;

		dbg_ck_hash("Moving item from table %u, key: %.*s, hash %u ",
		              next_table + 1, (int)(*moving)->key_length,
		              (*moving)->key, hash);

		// if rehashing and the 'next' item is from the old generation,
		// start from table 1
		if (generation != table->generation &&
		    EQUAL_GENERATIONS((*next)->timestamp, table->generation)) {
			next_table = 0;
		} else {
			ck_next_table(&next_table, table->table_count);
		}

		hash = HASH(&table->hash_system, (*next)->key,
		            (*next)->key_length, table->table_size_exp,
		            generation, next_table);

		next = &table->tables[next_table][hash];

		dbg_ck_hash("to table %u, hash %u, item: %p, place: %p\n",
		              next_table + 1, hash, *next, next);

		if ((*next) != NULL) {
			dbg_ck_hash("Table %u, hash: %u, key: %.*s\n",
			              next_table + 1, hash,
			              (int)(*next)->key_length, (*next)->key);
		}

		// check if this cell wasn't already used in this item's hashing
		if (ck_check_used_twice(&used[next_table], hash) != 0) {
			next = free;
			loop = -1;
			break;
		}
	}

	dbg_ck_hash("Putting pointer %p (*moving) to item %p (next).\n",
	              *moving, next);

	ck_put_item(next, *moving);
	// set the new generation for the inserted item
	SET_GENERATION(&(*next)->timestamp, generation);
	dbg_ck_hash("Putting pointer %p (*old) to item %p (moving).\n",
	              *to_hash, moving);

	ck_put_item(moving, *to_hash);

	// set the new generation for the inserted item
	SET_GENERATION(&(*moving)->timestamp, generation);
	*to_hash = NULL;

	for (uint i = 0; i < table->table_count; ++i) {
		da_destroy(&used[i]);
	}

	return loop;
}

/*----------------------------------------------------------------------------*/

static void ck_rollback_rehash(ck_hash_table_t *table)
{
	// set old generation in tables
	for (int i = 0; i < hashsize(table->table_size_exp); ++i) {
		// no need for locking - timestamp is not used in lookup
		// and two paralel insertions (and thus rehashings) are
		// impossible
		for (uint t = 0; t < table->table_count; ++t) {
			if (table->tables[t][i] != NULL) {
				SET_GENERATION(&table->tables[t][i]->timestamp,
				               table->generation);
			}
		}
	}

	// set old generation in stash
	ck_stash_item_t *item = table->stash;
	while (item != NULL) {
		assert(item->item != NULL);
		SET_GENERATION(&item->item->timestamp, table->generation);
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Adds the given item to the hash table's stash.
 *
 * \param table Hash table to add the item to.
 * \param item Item to add.
 *
 * \retval 0 if successful.
 * \retval -1 if an error occured.
 */
int ck_add_to_stash(ck_hash_table_t *table, ck_hash_table_item_t *item)
{
	ck_stash_item_t *new_item
		= (ck_stash_item_t *)malloc(sizeof(ck_stash_item_t));
	if (new_item == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	new_item->item = item;
	new_item->next = table->stash;
	table->stash = new_item;

	dbg_ck_hash("First item in stash (now inserted): key: %.*s (size %zu)"
	              ", value: %p\n", (int)table->stash->item->key_length,
	              table->stash->item->key, table->stash->item->key_length,
	              table->stash->item->value);
	
	// increase count of items in stash
	++table->items_in_stash;
	
	return 0;
}

/*----------------------------------------------------------------------------*/

static int ck_new_table(ck_hash_table_item_t ***table, int exp)
{
	*table = (ck_hash_table_item_t **)
	          malloc(hashsize(exp) * sizeof(ck_hash_table_item_t *));
	if (*table == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	// set to 0
	memset(*table, 0, hashsize(exp) * sizeof(ck_hash_table_item_t *));
	
	return 0;
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

ck_hash_table_t *ck_create_table(uint items)
{
	ck_hash_table_t *table =
			(ck_hash_table_t *)malloc(sizeof(ck_hash_table_t));

	if (table == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	
	memset(table, 0, sizeof(ck_hash_table_t));

	// determine ideal size of one table in powers of 2 and save the
	// exponent
	table->table_size_exp = get_table_exp_and_count(items,
	                                                &table->table_count);
	assert(table->table_size_exp <= 32);
	
	if (table->table_size_exp == 0) {
		dbg_ck("Failed to count exponent of the hash table.\n");
		return NULL;
	}

	dbg_ck("Creating hash table for %u items.\n", items);
	dbg_ck("Exponent: %u, number of tables: %u\n ",
		 table->table_size_exp, table->table_count);
	dbg_ck("Table size: %u items, each %zu bytes, total %zu bytes\n",
	         hashsize(table->table_size_exp),
	         sizeof(ck_hash_table_item_t *),
	         hashsize(table->table_size_exp)
	           * sizeof(ck_hash_table_item_t *));

	// create tables
	for (uint t = 0; t < table->table_count; ++t) {
		dbg_ck("Creating table %u...\n", t);
		if (ck_new_table(&table->tables[t], table->table_size_exp) 
		    != 0) {
			for (uint i = 0; i < t; ++i) {
				free(table->tables[i]);
			}
			free(table);
			return NULL;
		}
	}

	assert(table->stash == NULL);
	assert(table->hashed == NULL);
	assert(table->items == 0);
	assert(table->items_in_stash == 0);
	assert(table->table_count == MAX_TABLES
	       || table->tables[table->table_count] == NULL);

	// initialize rehash/insert mutex
	pthread_mutex_init(&table->mtx_table, NULL);

	// set the generation to 1 and initialize the universal system
	CLEAR_FLAGS(&table->generation);
	SET_GENERATION1(&table->generation);

	us_initialize(&table->hash_system);

	return table;
}

/*----------------------------------------------------------------------------*/

void ck_destroy_table(ck_hash_table_t **table, void (*dtor_value)(void *value),
                      int delete_key)
{
	assert(table);
	assert(*table);
	pthread_mutex_lock(&(*table)->mtx_table);

	// destroy items in tables
	for (uint i = 0; i < hashsize((*table)->table_size_exp); ++i) {
		for (uint t = 0; t < (*table)->table_count; ++t) {
			if ((*table)->tables[t][i] != NULL) {
				if (dtor_value) {
					dtor_value(
					  (*table)->tables[t][i]->value);
				}
				if (delete_key != 0) {
					free(
					  (void *)(*table)->tables[t][i]->key);
				}
				free((void *)(*table)->tables[t][i]);
			}
		}
	}

	// destroy items in stash
//	ck_hash_table_item_t **stash =
//	        ((ck_hash_table_item_t **)(da_get_items(&(*table)->stash)));
//	for (uint i = 0; i < da_get_count(&(*table)->stash); ++i) {
//		assert(stash[i] != NULL);
//		if (dtor_value) {
//			dtor_value(stash[i]->value);
//		}
//		if (delete_key != 0) {
//			free((void *)stash[i]->key);
//		}
//		free((void *)stash[i]);
//	}
	ck_stash_item_t *item = (*table)->stash;
	while (item != NULL) {
		// disconnect the item
		(*table)->stash = item->next;
		/*! \todo Investigate this. */
		assert(item->item != NULL);

		if (dtor_value) {
			dtor_value(item->item->value);
		}
		if (delete_key) {
			free((void *)item->item->key);
		}

		free((void *)item->item);
		free(item);
		item = (*table)->stash;
	}

	// deallocate tables
	for (uint t = 0; t < (*table)->table_count; ++t) {
		free((*table)->tables[t]);
	}
	// destroy stash
//	da_destroy(&(*table)->stash);

	pthread_mutex_unlock(&(*table)->mtx_table);
	// destroy mutex, assuming that here noone will lock the mutex again
	pthread_mutex_destroy(&(*table)->mtx_table);

	free(*table);
	(*table) = NULL;
}

void ck_table_free(ck_hash_table_t **table)
{
	if (table == NULL || *table == NULL) {
		return;
	}
	
	pthread_mutex_lock(&(*table)->mtx_table);

	ck_stash_item_t *item = (*table)->stash;
	while (item != NULL) {
		// disconnect the item
		(*table)->stash = item->next;
		free(item);
		item = (*table)->stash;
	}

	// deallocate tables
	for (uint t = 0; t < (*table)->table_count; ++t) {
		free((*table)->tables[t]);
	}

	pthread_mutex_unlock(&(*table)->mtx_table);
	pthread_mutex_destroy(&(*table)->mtx_table);

	free(*table);
	(*table) = NULL;
}

int ck_resize_table(ck_hash_table_t *table)
{
	dbg_ck("Resizing hash table.\n");
	
	/*
	 * Easiest is just to increment the exponent, resulting in doubling
	 * the table sizes. This is not very memory-effective, but should do
	 * the job.
	 */
	
	if (table->table_size_exp == 31) {
		dbg_ck("Hash tables achieved max size (exponent 31).\n");
		return -1;
	}
	
	ck_hash_table_item_t **tables_new[MAX_TABLES];
	ck_hash_table_item_t **tables_old[MAX_TABLES];
	int exp_new = table->table_size_exp + 1;
	
	dbg_ck("New tables exponent: %d\n", exp_new);
	
	for (int t = 0; t < table->table_count; ++t) {
		if (ck_new_table(&tables_new[t], exp_new) != 0) {
			dbg_ck("Failed to create new table.\n");
			for (int i = 0; i < t; ++i) {
				free(tables_new[i]);
			}
			return -1;
		}
	}
	
	dbg_ck("Created new tables, copying data to them.\n");
	
	for (int t = 0; t < table->table_count; ++t) {
		size_t old_size = hashsize(table->table_size_exp) 
		                  * sizeof(ck_hash_table_item_t *);
		
		// copy the old table items
		dbg_ck("Copying to: %p, from %p, size: %zu\n",
		         tables_new[t], table->tables[t], old_size);
		memcpy(tables_new[t], table->tables[t], old_size);
		// set the rest to 0
		dbg_ck("Setting to 0 from %p, size %zu\n",
		         tables_new[t] + hashsize(table->table_size_exp),
		         (hashsize(exp_new) * sizeof(ck_hash_table_item_t *))
		         - old_size);
		memset(tables_new[t] + hashsize(table->table_size_exp), 0, 
		       (hashsize(exp_new) * sizeof(ck_hash_table_item_t *))
		       - old_size);
	}
	
	dbg_ck("Done, switching the tables and running rehash.\n");
	
	
	memcpy(tables_old, table->tables, 
	       MAX_TABLES * sizeof(ck_hash_table_item_t **));
	memcpy(table->tables, tables_new, 
	       MAX_TABLES * sizeof(ck_hash_table_item_t **));
	
	table->table_size_exp = exp_new;
	
	// delete the old tables
	for (int t = 0; t < table->table_count; ++t) {
		free(tables_old[t]);
	}
	
	return ck_rehash(table);
	//return 0;
}

int ck_insert_item(ck_hash_table_t *table, const char *key,
                   size_t length, void *value)
{
	// lock mutex to avoid write conflicts
	pthread_mutex_lock(&table->mtx_table);

	assert(value != NULL);

	dbg_ck_hash("Inserting item with key: %.*s.\n", (int)length, key);
	dbg_ck_hash_hex(key, length);
	dbg_ck_hash("\n");

	// create item structure and fill in the given data, key won't be copied
	ck_hash_table_item_t *new_item =
	        (ck_hash_table_item_t *)malloc((sizeof(ck_hash_table_item_t)));
	ck_fill_item(key, length, value, GET_GENERATION(table->generation),
	             new_item);
	
	// check if the table is not full; if yes, resize and rehash!
	if (ck_is_full(table)) {
		dbg_ck("Table is full, resize needed.\n");
		if (ck_resize_table(table) != 0) {
			dbg_ck("Failed to resize hash table!\n");
			return -1;
		}
	}

	// there should be at least 2 free places
	//assert(da_try_reserve(&table->stash, 2) == 0);
	//da_reserve(&table->stash, 1);
	ck_hash_table_item_t *free_place = NULL;
	if (ck_hash_item(table, &new_item, &free_place,
	                 table->generation) != 0) {

		dbg_ck("Adding item with key %.*s to stash.\n",
		         (int)free_place->key_length, free_place->key);

		// maybe some limit on the stash and rehash if full
		if (ck_add_to_stash(table, free_place) != 0) {
			dbg_ck_hash("Could not add item to stash!!\n");
			assert(0);
		}
		
		if (ck_stash_is_full(table)) {
			dbg_ck("Stash is full, resize needed.\n");
			if (ck_resize_table(table) != 0) {
				dbg_ck("Failed to resize hash table!\n");
				return -1;
			}
		}
	}

	++table->items;
	pthread_mutex_unlock(&table->mtx_table);
	return 0;
}

/*----------------------------------------------------------------------------*/

const ck_hash_table_item_t *ck_find_item(const ck_hash_table_t *table,
                                         const char *key, size_t length)
{
	dbg_ck("ck_find_item(), key: %.*s, size: %zu\n",
	         (int)length, key, length);

	ck_hash_table_item_t **found = ck_find_item_nc(table, key, length);

	return (found == NULL) ? NULL : rcu_dereference(*found);
}

/*----------------------------------------------------------------------------*/

int ck_update_item(const ck_hash_table_t *table, const char *key, size_t length,
                   void *new_value, void (*dtor_value)(void *value))
{
	rcu_read_lock();	// is needed?

	assert(new_value != NULL);

	ck_hash_table_item_t **item = ck_find_item_nc(table, key, length);

	if (item == NULL || (*item) == NULL) {
		return -1;
	}

	void *old = rcu_xchg_pointer(&(*item)->value, new_value);
	rcu_read_unlock();

	synchronize_rcu();
	if (dtor_value) {
		dtor_value(old);
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int ck_delete_item(const ck_hash_table_t *table, const char *key, size_t length,
                   void (*dtor_value)(void *value), int delete_key)
{
	rcu_read_lock();	// is needed?
	ck_hash_table_item_t **place = ck_find_item_nc(table, key, length);

	if (place == NULL) {
		return -1;
	}

	ck_hash_table_item_t *item = *place;

	assert(item != NULL);

	ck_put_item(place, NULL);
	rcu_read_unlock();

	synchronize_rcu();
	if (dtor_value) {
		dtor_value(item->value);
	}
	item->value = NULL;
	if (delete_key != 0) {
		free((void *)item->key);
	}
	free(item);

	return 0;
}

/*----------------------------------------------------------------------------*/

ck_hash_table_item_t *ck_remove_item(ck_hash_table_t *table, const char *key, 
                                     size_t length)
{
	ck_hash_table_item_t **place = ck_find_item_nc(table, key, length);
	if (place == NULL) {
		return NULL;
	}
	
	ck_hash_table_item_t *item = *place;
	*place = NULL;
	return item;
}

/*----------------------------------------------------------------------------*/

int ck_shallow_copy(const ck_hash_table_t *from, ck_hash_table_t **to)
{
	if (from == NULL || to == NULL) {
		return -1;
	}

	*to = (ck_hash_table_t *)malloc(sizeof(ck_hash_table_t));

	if (*to == NULL) {
		ERR_ALLOC_FAILED;
		return -2;
	}
	memset(*to, 0, sizeof(ck_hash_table_t));

	// copy table count and table size exponent
	(*to)->table_size_exp = from->table_size_exp;
	(*to)->table_count = from->table_count;
	assert((*to)->table_size_exp <= 32);

	dbg_ck("Creating hash table for %u items.\n", from->table_count);
	dbg_ck("Exponent: %u, number of tables: %u\n ",
		 (*to)->table_size_exp, (*to)->table_count);
	dbg_ck("Table size: %u items, each %zu bytes, total %zu bytes\n",
	         hashsize((*to)->table_size_exp),
	         sizeof(ck_hash_table_item_t *),
	         hashsize((*to)->table_size_exp)
	           * sizeof(ck_hash_table_item_t *));

	// create tables
	for (uint t = 0; t < (*to)->table_count; ++t) {
		dbg_ck("Creating table %u...\n", t);
		(*to)->tables[t] = (ck_hash_table_item_t **)malloc(
		                        hashsize((*to)->table_size_exp)
		                        * sizeof(ck_hash_table_item_t *));
		if ((*to)->tables[t] == NULL) {
			ERR_ALLOC_FAILED;
			for (uint i = 0; i < t; ++i) {
				free((*to)->tables[i]);
			}
			free(*to);
			return -2;
		}

		// copy the table
		memcpy((*to)->tables[t], from->tables[t],
		       hashsize((*to)->table_size_exp)
		           * sizeof(ck_hash_table_item_t *));
	}

	// copy the stash - we must explicitly copy each stash item, but do not
	// copy the ck_hash_table_item_t within them.
	ck_stash_item_t *si = from->stash;
	ck_stash_item_t **pos = &(*to)->stash;
	dbg_ck_verb("Copying hash table stash.\n");
	while (si != NULL) {
		ck_stash_item_t *si_new = (ck_stash_item_t *)
		                           malloc(sizeof(ck_stash_item_t));
		if (si_new == NULL) {
			ERR_ALLOC_FAILED;
			// delete tables
			for (uint i = 0; i < (*to)->table_count; ++i) {
				free((*to)->tables[i]);
			}
			// delete created stash items
			si_new = (*to)->stash;
			while (si_new != NULL) {
				ck_stash_item_t *prev = si_new;
				si_new = si_new->next;
				free(prev);
			}
			free(*to);
			return -2;
		}

		dbg_ck("Copying stash item: %p with item %p, ", si, si->item);
		dbg_ck("key: %.*s\n", (int)si->item->key_length, si->item->key);

		si_new->item = si->item;
		*pos = si_new;
		pos = &si_new->next;
		si = si->next;


		dbg_ck("Old stash item: %p with item %p, ", si,
		       ((si == NULL) ? NULL : si->item));
		if (si != NULL) {
			dbg_ck("key: %.*s\n", (int)si->item->key_length, si->item->key);
		} else {
			dbg_ck("\n");
		}
		dbg_ck("New stash item: %p with item %p, ", si_new,
		       si_new->item);
		dbg_ck("key: %.*s\n", (int)si_new->item->key_length, 
		       si_new->item->key);
	}
	
	*pos = NULL;
	
	// there should be no item being hashed right now
	/*! \todo This operation should not be done while inserting / rehashing. 
	 */
	assert(from->hashed == NULL);
	(*to)->hashed = NULL;
	
	// initialize rehash/insert mutex
	pthread_mutex_init(&(*to)->mtx_table, NULL);

	// copy the generation
	(*to)->generation = from->generation;
	
	// copy the hash functions
	memcpy(&(*to)->hash_system, &from->hash_system, sizeof(us_system_t));
	
	return 0;
}

/*----------------------------------------------------------------------------*/

static int ck_copy_items(ck_hash_table_item_t **from,
                         ck_hash_table_item_t **to, uint32_t count)
{
	assert(from != NULL);
	assert(to != NULL);

	for (int i = 0; i < count; ++i) {
		if (from[i] != NULL) {
			to[i] = (ck_hash_table_item_t *)
				malloc(sizeof(ck_hash_table_item_t));

			if (to[i] == NULL) {
				return -2;
			}

			memcpy(to[i], from[i], sizeof(ck_hash_table_item_t));
		} else {
			to[i] = NULL;
		}
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

void ck_deep_copy_cleanup(ck_hash_table_t *table, int table_count)
{
	// free tables with their items
	for (int t = 0; t < table_count; ++t) {
		for (int i = 0; i < hashsize(table->table_size_exp); ++i) {
			free(table->tables[t][i]);
		}
		free(table->tables[t]);
	}

	// free stash items with hash table items in them
	ck_stash_item_t *si = table->stash;
	ck_stash_item_t *to_free;
	while (si != NULL) {
		to_free = si;
		si = si->next;
		free(to_free->item);
		free(to_free);
	}

	free(table);
}

/*----------------------------------------------------------------------------*/

int ck_deep_copy(ck_hash_table_t *from, ck_hash_table_t **to)
{
	if (from == NULL || to == NULL) {
		return -1;
	}

	dbg_ck("Allocating new table...\n");
	*to = (ck_hash_table_t *)malloc(sizeof(ck_hash_table_t));

	if (*to == NULL) {
		ERR_ALLOC_FAILED;
		return -2;
	}
	memset(*to, 0, sizeof(ck_hash_table_t));

	// copy table count and table size exponent
	(*to)->table_size_exp = from->table_size_exp;
	(*to)->table_count = from->table_count;
	assert((*to)->table_size_exp <= 32);

	dbg_ck("Creating hash table for %u items.\n", from->table_count);
	dbg_ck("Exponent: %u, number of tables: %u\n ",
		 (*to)->table_size_exp, (*to)->table_count);
	dbg_ck("Table size: %u items, each %zu bytes, total %zu bytes\n",
	         hashsize((*to)->table_size_exp),
	         sizeof(ck_hash_table_item_t *),
	         hashsize((*to)->table_size_exp)
	           * sizeof(ck_hash_table_item_t *));

	// create tables
	for (uint t = 0; t < (*to)->table_count; ++t) {
		dbg_ck("Creating table %u...\n", t);
		(*to)->tables[t] = (ck_hash_table_item_t **)malloc(
		                        hashsize((*to)->table_size_exp)
		                        * sizeof(ck_hash_table_item_t *));
		if ((*to)->tables[t] == NULL) {
			ERR_ALLOC_FAILED;
			for (uint i = 0; i < t; ++i) {
				free((*to)->tables[i]);
			}
			free(*to);
			return -2;
		}

		// copy the table with all hash table items
		dbg_ck("Copying table %u...\n", t);
		int ret = ck_copy_items(from->tables[t], (*to)->tables[t],
		                        hashsize((*to)->table_size_exp));
		if (ret != 0) {
			dbg_ck("Failed!\n");
			// free all tables created until now
			ck_deep_copy_cleanup(*to, t);
			return ret;
		}
	}

	// copy the stash - we must explicitly copy each stash item,
	// together with the hash table item stored in it
	ck_stash_item_t *si = from->stash;
	ck_stash_item_t **pos = &(*to)->stash;
	dbg_ck_verb("Copying hash table stash.\n");
	while (si != NULL) {
		ck_stash_item_t *si_new = (ck_stash_item_t *)
		                           malloc(sizeof(ck_stash_item_t));
		if (si_new == NULL) {
			ERR_ALLOC_FAILED;
			ck_deep_copy_cleanup(*to, (*to)->table_count);
			return -2;
		}

		dbg_ck("Copying stash item: %p with item %p, ", si, si->item);
		dbg_ck("key: %.*s\n", (int)si->item->key_length, si->item->key);

		si_new->item = (ck_hash_table_item_t *)
		                malloc(sizeof(ck_hash_table_item_t));

		if (si_new->item == NULL) {
			ERR_ALLOC_FAILED;
			ck_deep_copy_cleanup(*to, (*to)->table_count);
			return -2;
		}

		memcpy(si_new->item, si->item, sizeof(ck_hash_table_item_t));

		*pos = si_new;
		pos = &si_new->next;
		si = si->next;


		dbg_ck("Old stash item: %p with item %p, ", si,
		       ((si == NULL) ? NULL : si->item));
		if (si != NULL) {
			dbg_ck("key: %.*s\n", (int)si->item->key_length, si->item->key);
		} else {
			dbg_ck("\n");
		}
		dbg_ck("New stash item: %p with item %p, ", si_new,
		       si_new->item);
		dbg_ck("key: %.*s\n", (int)si_new->item->key_length,
		       si_new->item->key);
	}

	*pos = NULL;

	// there should be no item being hashed right now
	/*! \todo This operation should not be done while inserting / rehashing.
	 */
	assert(from->hashed == NULL);
	(*to)->hashed = NULL;

	// initialize rehash/insert mutex
	pthread_mutex_init(&(*to)->mtx_table, NULL);

	// copy the generation
	(*to)->generation = from->generation;

	// copy the hash functions
	memcpy(&(*to)->hash_system, &from->hash_system, sizeof(us_system_t));

	return 0;
}

/*----------------------------------------------------------------------------*/

int ck_apply(ck_hash_table_t *table,
             void (*function)(ck_hash_table_item_t *item, void *data), 
             void *data)
{
	if (table == NULL || function == NULL) {
		return -1;
	}
	
	/*! \todo Ensure that no insertion nor rehash is made during applying.*/
	
	// apply the function to all items in all tables
	for (int t = 0; t < table->table_count; ++t) {
		for (int i = 0; i < hashsize(table->table_size_exp); ++i) {
			function(table->tables[t][i], data);
		}
	}
	
	// apply the function to the stash items
	ck_stash_item_t *si = table->stash;
	while (si != NULL) {
		function(si->item, data);
		si = si->next;
	}
	
	return 0;
}

/*----------------------------------------------------------------------------*/

int ck_rehash(ck_hash_table_t *table)
{
	dbg_ck_hash("Rehashing items in table.\n");
	SET_REHASHING_ON(&table->generation);

	ck_stash_item_t *free_stash_items = NULL;

	do {
		// 1) Rehash items from stash
		dbg_ck_rehash("Rehashing items from stash.\n");
		ck_stash_item_t *item = table->stash;
		ck_stash_item_t **item_place = &table->stash;
		// terminate when at the end; this way the newly added items
		// (added to the beginning) will be properly ignored
		while (item != NULL) {
			dbg_ck_rehash("Rehashing item with "
			  "key (length %zu): %.*s, generation: %hu, "
			  "table generation: %hu.\n", item->item->key_length,
			  (int)item->item->key_length, item->item->key,
			  GET_GENERATION(
				item->item->timestamp),
			  GET_GENERATION(table->generation));

			// put the hashed item to the prepared space
			table->hashed = item->item;
			item->item = NULL;
			// we may use the place in the stash item as the free
			// place for rehashing
			if (ck_hash_item(table, &table->hashed, &item->item,
			             NEXT_GENERATION(table->generation)) != 0) {
				// the free place was used
				assert(item->item != NULL);
				// we may leave the item there (in the stash)
				assert(EQUAL_GENERATIONS(item->item->timestamp,
				           NEXT_GENERATION(table->generation)));
				//assert(item->item == table->hashed);

				item_place = &item->next;
				item = item->next;
			} else {
				// the free place should be free
				assert(item->item == NULL);
				// and the item should be hashed too
//				assert(table->hashed == NULL);

				// fix the pointer from the previous hash item
				*item_place = item->next;
				// and do not change the item place pointer

				// put the stash item into list of free stash
				// items
				item->next = free_stash_items;
				free_stash_items = item;

				item = *item_place;
			}
		}

		// 2) Rehash items from tables

		// in case of failure, save the item in a temp variable
		// which will be put to the stash
		ck_hash_table_item_t *free = NULL;
		assert(table->hashed == NULL);
//		ck_hash_table_item_t *old = table->hashed;

		for (uint t = 0; t < table->table_count; ++t) {
			uint rehashed = 0;

			dbg_ck_rehash("Rehashing table %d.\n", t);

			while (rehashed < hashsize(table->table_size_exp)) {

				// if item's generation is the new generation,
				// skip
				if (table->tables[t][rehashed] == NULL
				    || !(EQUAL_GENERATIONS(
				          table->tables[t][rehashed]->timestamp,
				          table->generation))) {
					dbg_ck_rehash("Skipping item.\n");
					++rehashed;
					continue;
				}

				dbg_ck_rehash("Rehashing item with hash %u, "
				  "key (length %zu): %.*s, generation: %hu, "
				  "table generation: %hu.\n", rehashed,
				  table->tables[t][rehashed]->key_length,
				  (int)(table->tables[t][rehashed]->key_length),
				  table->tables[t][rehashed]->key,
				  GET_GENERATION(
					table->tables[t][rehashed]->timestamp),
				  GET_GENERATION(table->generation));

				// otherwise copy the item for rehashing
				ck_put_item(&table->hashed, table->tables[t][rehashed]);
				// clear the place so that this item will not
				// get rehashed again
				ck_clear_item(&table->tables[t][rehashed]);

				dbg_ck_rehash("Table generation: %hu, next "
				            "generation: %hu.\n",
				            GET_GENERATION(table->generation),
				            NEXT_GENERATION(table->generation));

				if (ck_hash_item(table, &table->hashed, &free,
				     NEXT_GENERATION(table->generation)) != 0) {
					// loop occured
					dbg_ck_hash("Hashing entered a loop."
						      "\n");
					dbg_ck_rehash("Item with key %.*s "
					  "inserted into the free slot.\n",
					  free->key_length, free->key);

					//assert(old == free);

					// put the item into the stash, but
					// try the free stash items first
					if (free_stash_items != NULL) {
						// take first
						ck_stash_item_t *item =
							free_stash_items;
						free_stash_items = item->next;

						item->item = free;
						item->next = table->stash;
						table->stash = item;
					} else {
						if (ck_add_to_stash(table, free)
						    != 0) {
							ck_rollback_rehash(
								table);
						}
					}

					free = NULL;
					table->hashed = NULL;
				}
				++rehashed;
			}
		}

		dbg_ck_rehash("Old table generation: %u\n",
		                GET_GENERATION(table->generation));
		// rehashing completed, switch generation of the table
		SET_NEXT_GENERATION(&table->generation);
		dbg_ck_rehash("New table generation: %u\n",
		                GET_GENERATION(table->generation));
		// generate new hash functions for the old generation
		dbg_ck_rehash("Generating coeficients for generation: %u\n",
		                NEXT_GENERATION(table->generation));
		us_next(&table->hash_system,
		        NEXT_GENERATION(table->generation));

	} while (false /*! \todo Add proper condition!! */);

	SET_REHASHING_OFF(&table->generation);

	assert(table->hashed == NULL);


	while (free_stash_items != NULL) {
		ck_stash_item_t *item = free_stash_items;
		free_stash_items = item->next;
		assert(item->item == NULL);
		free(item);
	}

	return 0;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Rehashes the whole table.
 *
 * \param table Hash table to be rehashed.
 *
 * \note While rehashing no item should be inserted as it will result in a
 *       deadlock.
 *
 * \retval 0 No error.
 * \retval -1 Rehashing failed. Some items may have been already moved and the
 *            rehashing flag remains set.
 *
 * \todo What if the stash is reallocated during ck_hash_item()? We'd be using
 *       the old stash for saving items! The old stash would not get deallocated
 *       (due to RCU - maybe put some rcu_read_lock() here), but the item
 *       would not be saved into the new stash!
 *       Maybe add a function for getting a pointer to particular item from
 *       the dynamic array and protect it using rcu_read_lock().
 *       Other option: Do not use pointer to an item in stash in the call to
 *       ck_hash_item(). Use some new place & put the item to the stash
 *       afterwards, protecting it using rcu_read_lock() and rcu_assign_pointer.
 */
//int ck_rehash(ck_hash_table_t *table)
//{
//	dbg_ck_rehash("Rehashing items in table.\n");
//	SET_REHASHING_ON(&table->generation);

//	// we already have functions for the next generation, begin rehashing
//	// we wil use the last item in the buffer as free cell for hashing
//	assert(da_try_reserve(&table->stash, 1) == 0);
//	ck_hash_table_item_t *old = (ck_hash_table_item_t *)
//	                          (malloc(sizeof(ck_hash_table_item_t)));

//	do {
//		dbg_ck_hash("Rehash!\n");

//		if (da_get_count(&table->stash) > STASH_SIZE) {
//			dbg_ck_hash("STASH RESIZED!!! (new stash size: %d)\n",
//			              da_get_count(&table->stash));
//		}

//		// rehash items from stash, starting from the last old item
//		int stash_i = da_get_count(&table->stash) - 1;
//		while (stash_i >= 0) {
//			// if item's generation is the new generation, skip
//			if (STASH_ITEMS(&table->stash)[stash_i] == NULL
//			    || !(EQUAL_GENERATIONS(STASH_ITEMS(&table->stash)
//			                            [stash_i]->timestamp,
//			                            table->generation))) {
//				dbg_ck_rehash("Skipping item.\n");
//				--stash_i;
//				continue;
//			}

//			dbg_ck_rehash("Rehashing item from buffer position %u"
//			                ", key (length %u): %.*s, generation: "
//			                "%hu, table generation: %hu.\n",
//			   stash_i,
//			   STASH_ITEMS(&table->stash)[stash_i]->key_length,
//			   (int)STASH_ITEMS(&table->stash)[stash_i]->key_length,
//			   STASH_ITEMS(&table->stash)[stash_i]->key,
//			   GET_GENERATION(
//				STASH_ITEMS(&table->stash)[stash_i]->timestamp),
//			   GET_GENERATION(table->generation));

//			// otherwise copy the item for rehashing
//			ck_put_item(&old, STASH_ITEMS(&table->stash)[stash_i]);
//			// clear the place so that this item will not get
//			// rehashed again
//			ck_clear_item(&STASH_ITEMS(&table->stash)[stash_i]);
//			da_release(&table->stash, 1);

//			// there should be at least one place in the stash
//			assert(da_try_reserve(&table->stash, 1) == 0);
//			da_reserve(&table->stash, 1);

//			assert(STASH_ITEMS(&table->stash)[stash_i] == NULL);

//			// and start rehashing
//			if (ck_hash_item(table, &old,
//			             &STASH_ITEMS(&table->stash)[stash_i],
//			             NEXT_GENERATION(table->generation)) != 0) {
//				// loop occured
//				dbg_ck_hash("Hashing entered a loop.\n");

//				dbg_ck_rehash("Item with key %.*s inserted "
//					"into the stash on position %d.\n",
//					STASH_ITEMS(&table->stash)
//						[stash_i]->key_length,
//					STASH_ITEMS(&table->stash)
//						[stash_i]->key,
//					da_get_count(&table->stash));

//				// hashing unsuccessful, the item was inserted
//				// into the stash
//				da_occupy(&table->stash, 1);
//				assert(STASH_ITEMS(&table->stash)[stash_i]
//				       != NULL);

//				// if only one place left, resize the stash
//				// TODO: Why???
//				if (da_reserve(&table->stash, 2) < 0) {
//					// stash could not be resized => !!!
//					dbg_ck_hash("Failed to rehash items "
//					              "from "
//					  "table, no other rehash possible!\n");
//					// so rollback
//					ck_rollback_rehash(table);
//					// clear the 'old' item
//					ck_clear_item(&old);
//					return -1;
//				}
//			}

//			// clear the 'old' item
//			ck_clear_item(&old);
//			// decrement the index
//			--stash_i;
//		}

//		uint i = 0;
//		while (i < da_get_count(&table->stash)) {
//			assert(STASH_ITEMS(&table->stash)[i] != NULL);
//			++i;
//		}
//		dbg_ck_hash("OK\n");
//		assert(da_try_reserve(&table->stash, 1) == 0);
//		assert(STASH_ITEMS(&table->stash)[da_get_count(&table->stash)]
//		       == NULL);

//		// rehash items from hash tables
//		for (uint t = TABLE_FIRST;
//		     t <= TABLE_LAST(table->table_count); ++t) {
//			dbg_ck_rehash("Rehashing items from table %d.\n",
//			                t + 1);
//			uint rehashed = 0;

//			while (rehashed < hashsize(table->table_size_exp)) {

//				// if item's generation is the new generation,
//				// skip
//				if (table->tables[t][rehashed] == NULL
//				    || !(EQUAL_GENERATIONS(
//				          table->tables[t][rehashed]->timestamp,
//				          table->generation))) {
//					dbg_ck_rehash("Skipping item.\n");
//					++rehashed;
//					continue;
//				}

//				dbg_ck_rehash("Rehashing item with hash %u, "
//				  "key (length %u): %.*s, generation: %hu, "
//				  "table generation: %hu.\n", rehashed,
//				  table->tables[t][rehashed]->key_length,
//				  (int)(table->tables[t][rehashed]->key_length),
//				  table->tables[t][rehashed]->key,
//				  GET_GENERATION(
//					table->tables[t][rehashed]->timestamp),
//				  GET_GENERATION(table->generation));

//				// otherwise copy the item for rehashing
//				ck_put_item(&old, table->tables[t][rehashed]);
//				// clear the place so that this item will not
//				// get rehashed again
//				ck_clear_item(&table->tables[t][rehashed]);

//				dbg_ck_rehash("Table generation: %hu, next "
//				            "generation: %hu.\n",
//				            GET_GENERATION(table->generation),
//				            NEXT_GENERATION(table->generation));

//				// and start rehashing
//				assert(&old != &STASH_ITEMS(&table->stash)[
//				               da_get_count(&table->stash)]);
//				assert(da_try_reserve(&table->stash, 1) == 0);
//				da_reserve(&table->stash, 1);

//				if (ck_hash_item(table, &old,
//				     &STASH_ITEMS(&table->stash)[
//				       da_get_count(&table->stash)],
//				     NEXT_GENERATION(table->generation)) != 0) {
//					// loop occured
//					dbg_ck_hash("Hashing entered a loop."
//						      "\n");
//					dbg_ck_rehash("Item with key %.*s "
//					  "inserted into the stash on position "
//					  "%d.\n", STASH_ITEMS(&table->stash)[
//					      da_get_count(&table->stash)]
//					         ->key_length,
//					  STASH_ITEMS(&table->stash)[
//					      da_get_count(&table->stash)]->key,
//					  da_get_count(&table->stash));

//					assert(STASH_ITEMS(&table->stash)[
//					  da_get_count(&table->stash)] != NULL);
//					// loop occured, the item is already at
//					// its new place in the buffer, so just
//					// increment the index
//					da_occupy(&table->stash, 1);

//					// if only one place left, resize the
//					// stash TODO: Why?
//					if (da_reserve(&table->stash, 2) < 0) {
//						// stash could not be resized
//						dbg_ck_hash("Failed to rehash"
//						  " items from table, no other "
//						  "rehash possible!\n");
//						// so rollback
//						ck_rollback_rehash(table);
//						// clear the 'old' item
//						ck_clear_item(&old);
//						return -1;
//					}
//				}
//				++rehashed;
//			}
//		}

//		dbg_ck_rehash("Old table generation: %u\n",
//		                GET_GENERATION(table->generation));
//		// rehashing completed, switch generation of the table
//		SET_NEXT_GENERATION(&table->generation);
//		dbg_ck_rehash("New table generation: %u\n",
//		                GET_GENERATION(table->generation));
//		// generate new hash functions for the old generation
//		dbg_ck_rehash("Generating coeficients for generation: %u\n",
//		                NEXT_GENERATION(table->generation));
//		us_next(NEXT_GENERATION(table->generation));

//		// repeat rehashing while there are more items in the stash than
//		// its initial size
//		if (da_get_count(&table->stash) > STASH_SIZE) {
//			dbg_ck_rehash("Rehashing again!\n");
//		}
//	} while (da_get_count(&table->stash) > STASH_SIZE);

//	SET_REHASHING_OFF(&table->generation);

//	return 0;
//}

/*----------------------------------------------------------------------------*/

void ck_dump_table(const ck_hash_table_t *table)
{
#ifdef CUCKOO_DEBUG
	uint i = 0;
	dbg_ck("----------------------------------------------\n");
	dbg_ck("Hash table dump:\n\n");
	dbg_ck("Size of each table: %u\n\n", hashsize(table->table_size_exp));

	for (uint t = 0; t < table->table_count; ++t) {
		dbg_ck("Table %d:\n", t + 1);

		for (i = 0; i < hashsize(table->table_size_exp); i++) {
			dbg_ck("Hash: %u, Key: %.*s, Value: %p.\n", i,
			         (int)(table->tables[t])[i]->key_length,
			         (table->tables[t])[i]->key,
			         (table->tables[t])[i]->value);
		}
	}

	dbg_ck("Stash:\n");
//	for (i = 0; i < da_get_count(&table->stash); ++i) {
//		dbg_ck("Index: %u, Key: %.*s Value: %p.\n", i,
//		         ((ck_hash_table_item_t **)
//		             da_get_items(&table->stash))[i]->key_length,
//		         ((ck_hash_table_item_t **)
//		             da_get_items(&table->stash))[i]->key,
//		         ((ck_hash_table_item_t **)
//		             da_get_items(&table->stash))[i]->value);
//	}
	ck_stash_item_t *item = table->stash;
	while (item != NULL) {
		dbg_ck("Hash: %u, Key: %.*s, Value: %p.\n", i,
			 (int)item->item->key_length, item->item->key,
			 item->item->value);
		item = item->next;
	}

	dbg_ck("\n");
#endif
}
