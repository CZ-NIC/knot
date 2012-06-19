/*!
 * \file cuckoo-hash-table.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Implementation of Cuckoo hashing scheme.
 *
 * Uses d-ary Cuckoo hashing with stash.
 *
 * \todo Maybe provide some way to resize the whole table if the number of items
 *       grows too much.
 * \todo Check size of integers, the table size may be larger than unsigned int.
 * \todo Maybe do not return ck_hash_table_item from ck_find_item(), but only
 *       its value.
 * \todo When hashing an item, only the first table is tried for this item.
 *       We may try all tables. (But it is not neccessary.)
 *
 * \addtogroup hashing
 * @{
 */
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

#ifndef _KNOT_CUCKOO_HASH_TABLE_H_
#define _KNOT_CUCKOO_HASH_TABLE_H_

#include <stdint.h> /* uint32_t */
#include <stdlib.h> /* size_t */
#include <pthread.h>

#include "hash/universal-system.h"

/*----------------------------------------------------------------------------*/

/*! \brief Macro for getting one hash table size. */
#define hashsize(n) ((uint32_t)1 << (n))

/*!
 * \brief Max number of hash tables - must be the same as number of the hash
 *        functions in each generation of the universal system.
 */
#define MAX_TABLES US_FNC_COUNT

/*! \brief Default stash size. */
static const uint STASH_SIZE = 10;

/*! \brief Maximum stash size. When achieved, rehashing is needed. */
static const uint STASH_SIZE_MAX = 30;

/*----------------------------------------------------------------------------*/
/* Public structures                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for storing the hashed data.
 */
struct ck_hash_table_item {
	const char *key; /*!< Key of the item, used for hashing. */

	size_t key_length; /*!< Length of the key in octets. */

	void *value; /*!< The actual item stored in the table. */

	/*!
	 * \brief Flags. Currently used for keeping the generation of the item,
	 *        i.e. the generation of the functions used for hashing this
	 *        item.
	 *
	 * Form: 000000xy;
	 * xy - generation; may be 01 (1) or 10 (2).
	 */
	uint8_t timestamp;
};

typedef struct ck_hash_table_item ck_hash_table_item_t;

struct ck_stash_item {
	ck_hash_table_item_t *item;
	struct ck_stash_item *next;
};

typedef struct ck_stash_item ck_stash_item_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Hash table structure which uses cuckoo hashing.
 *
 * Keys are expected to be strings of characters (char *), not necesarily
 * null-terminated. It uses the Fowler/Noll/Vo (FNV) hash function to
 * obtain a 32bit unsigned integer from the character data and a function
 * randomly chosen from an universal system (see universal-system.h) to obtain
 * the final hash. The FNV hash was taken from
 * http://home.comcast.net/~bretm/hash/6.html and the universal system is
 * constructed according to Katajainen J., Lykke M., Experiments with universal
 * hashing (obtained from
 * http://www.diku.dk/OLD/publikationer/tekniske.rapporter/rapporter/96-08.pdf).
 *
 * The table uses either 3-ary or 4-ary cuckoo hashing (and thus 3 or 4 tables)
 * with stash, according to the number of items provided to ck_create_table()
 * function. The number of table pointers is however set to be the larger value
 * (4) always, so the \a tables array may be statically allocated. Size of one
 * table is always a power of 2 (due to the character of the hash function).
 * The stash has a default size STASH_SIZE, but can be resized if needed.
 * However, the resizing is only done in rehashing process, if the items do not
 * fit into the table and the original stash.
 *
 * Rehashing is done when the stash gets full (actually, last item is always
 * free and is used in the rehashing process as a temporary variable).
 */
struct ck_hash_table {
	uint table_count; /*!< Actual number of hash tables used. */

	/*!
	 * \brief Exponent of one table's size (2^table_size_exp is table size).
	 */
	int table_size_exp;

	ck_hash_table_item_t **tables[MAX_TABLES]; /*!< Array of hash tables. */

	//da_array_t stash; /*!< Stash implemented as a dynamic array. */
	ck_stash_item_t *stash;

	/*! \brief Temporary storage for item being hashed. */
	ck_hash_table_item_t *hashed;

	/*! \brief Mutex for avoiding multiple insertions / rehashes at once. */
	pthread_mutex_t mtx_table;

	/*!
	 * \brief Flags used for determining which hash functions are currently
	 *        used
	 *
	 * Form: 00000xyz.
	 * x - rehash flag (1 if rehashing is in progress)
	 * yz - generation (may be 10 = 2, or 01 = 1)
	 *
	 * There are always two sets of hash functions available via the
	 * us_hash() function (see universal-hashing.h). Normally all items in
	 * the table are hashed using one set of functions. However, during
	 * rehash, the other set is used for rehashing. In this case the rehash
	 * flag (x) is set, so the lookup function (ck_find_item()) tries to use
	 * both sets of functions when searching for item.
	 */
	uint8_t generation;

	us_system_t hash_system; /*!< Universal system of hash functions. */
	
	size_t items;
	size_t items_in_stash;
};

typedef struct ck_hash_table ck_hash_table_t;

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates and initializes the hash table structure.
 *
 * All hash tables are allocated and their items initialized to 0 (NULL).
 * A stash of default size is also created. The \a generation flags are set to
 * 0.
 *
 * \param items Number of items to be hashed to the table. This number
 *              determines the size of the hash table that will be created.
 *
 *
 * \return Pointer to the initialized hash table.
 */
ck_hash_table_t *ck_create_table(uint items);

/*----------------------------------------------------------------------------*/
/*!
 * \brief Destroys the whole hash table together with the saved values.
 *
 * \param table Pointer to pointer to the hash table.
 * \param dtor_value Destructor function for the values that are be stored in
 *                   the hash table. Set to NULL if you do not want the values
 *                   to be deleted.
 * \param delete_key Set to 0 if you do not want the function to delete the
 *                   key of the item (e.g. when used elsewhere). Set to any
 *                   other value otherwise.
 *
 * \note Make sure the table and its items are not used anymore when calling
 * this function.
 */
void ck_destroy_table(ck_hash_table_t **table,
                      void (*dtor_value)(void *value), int delete_key);

/*!
 * \brief Destroys the table structures, but does not remove the individual
 *        hash table items.
 */
void ck_table_free(ck_hash_table_t **table);

/*----------------------------------------------------------------------------*/
/*!
 * \brief Inserts item into the hash table.
 *
 * Insertion starts always by trying to hash the item into the first table. The
 * possible displaced item is then hashed into randomly chosen other table,
 * etc., until a free place is found or a loop occured. A loop occurs when one
 * position in one table is tried more than twice.
 *
 * \param table Hash table the item should be inserted into.
 * \param key Item's key. It can be any string of octets. The key is not copied
 *            by the function.
 * \param length Length of the key in bytes (octets).
 * \param value Pointer to the actual item to be inserted into the hash table.
 *
 * \note This function does not copy the key.
 * \note This function may trigger rehash of the whole table in case the stash
 *       gets full.
 *
 * \retval 0 No error.
 * \retval -1 Insertion failed. This may occur only when the rehashing fails.
 *            In this case it is necessary to somehow manually force another
 *            rehash as no other rehash would be possible.
 */
int ck_insert_item(ck_hash_table_t *table, const char *key, size_t length,
                   void *value);

/*----------------------------------------------------------------------------*/
/*!
 * \brief Finds item in table.
 *
 * \param table Hash table to search in.
 * \param key Key of the item. It can be an arbitrary string of octets.
 * \param length Length of the key in bytes (octets).
 *
 * \return Pointer to the item if found. NULL otherwise.
 */
const ck_hash_table_item_t *ck_find_item(const ck_hash_table_t *table,
                                         const char *key, size_t length);

/*----------------------------------------------------------------------------*/
/*!
 * \brief Updates item with the given key by replacing its value.
 *
 * The update process is synchronized using RCU mechanism, so the old item's
 * value will not be deleted while some thread is using it.
 *
 * \param table Hash table where to search for the item.
 * \param key Key of the item to be updated. It can be an arbitrary string of
 *            octets.
 * \param length Length of the key in bytes (octets).
 * \param new_value New value for the item with key \a key.
 * \param dtor_value Destructor function for the values that are be stored in
 *                   the hash table. Set to NULL if you do not want the values
 *                   to be deleted.
 *
 * \retval 0 If successful.
 * \retval -1 If the item was not found in the table. No changes are made.
 */
int ck_update_item(const ck_hash_table_t *table, const char *key, size_t length,
                   void *new_value, void (*dtor_value)(void *value));

/*----------------------------------------------------------------------------*/
/*!
 * \brief Removes item with the given key from table.
 *
 * The deletion process is synchronized using RCU mechanism, so the old item
 * will not be deleted while some thread is using it.
 *
 * \param table Hash table where to search for the item.
 * \param key Key of the item to be removed. It can be an arbitrary string of
 *            octets.
 * \param length Length of the key in bytes (octets).
 * \param dtor_value Destructor function for the values that are be stored in
 *                   the hash table. Set to NULL if you do not want the values
 *                   to be deleted.
 * \param delete_key Set to 0 if you do not want the function to delete the
 *                   key of the item (e.g. when used elsewhere). Set to any
 *                   other value otherwise.
 *
 * \retval 0 If successful.
 * \retval -1 If the item was not found in the table.
 */
int ck_delete_item(const ck_hash_table_t *table, const char *key, size_t length,
                   void (*dtor_value)(void *value), int delete_key);

ck_hash_table_item_t *ck_remove_item(ck_hash_table_t *table, const char *key, 
                                     size_t length);

/*!
 * \brief Creates a shallow copy of the cuckoo hash table.
 *
 * This function creates just the ck_hash_table_t structure and its tables and
 * stash. It does not copy individual ck_hash_table_item_t structures.
 *
 * \param from Table to copy.
 * \param to The new copy will be stored here.
 *
 * \retval 0 if successful.
 * \retval
 */
int ck_shallow_copy(const ck_hash_table_t *from, ck_hash_table_t **to);

int ck_deep_copy(ck_hash_table_t *from, ck_hash_table_t **to);

int ck_apply(ck_hash_table_t *table, 
             void (*function)(ck_hash_table_item_t *item, void *data), 
             void *data);

/*----------------------------------------------------------------------------*/

int ck_rehash(ck_hash_table_t *table);

// for testing purposes only
int ck_resize_table(ck_hash_table_t *table);

/*----------------------------------------------------------------------------*/
/*!
 * \brief Dumps the whole hash table to the standard output.
 */
void ck_dump_table(const ck_hash_table_t *table);

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_CUCKOO_HASH_TABLE_H_ */

/*! @} */
