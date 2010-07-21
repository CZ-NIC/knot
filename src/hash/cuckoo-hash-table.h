/*!
 * @file cuckoo-hash-table.h
 *
 * @todo Maybe provide some way to resize the whole table if the number of items
 *       grows too much.
 * @todo Check size of integers, the table size may be larger than unsigned int.
 */
#ifndef CUCKOO_HASH_TABLE
#define CUCKOO_HASH_TABLE

#include <stdint.h>	/* uint32_t */
#include <stdlib.h>	/* size_t */
#include <pthread.h>
#include "common.h"

#include "universal-system.h"
#include "dynamic-array.h"

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

#define MAX_TABLES US_FNC_COUNT
/*!
 * @brief Default stash size.
 */
static const uint STASH_SIZE = 10;

/*----------------------------------------------------------------------------*/
/* Public structures							                              */
/*----------------------------------------------------------------------------*/

typedef struct {
	const char *key;
	size_t key_length;
	void *value;
	uint8_t timestamp;	// 000000xy; xy .. generation; may be 01 or 10
} ck_hash_table_item;	// size 13 B

/*----------------------------------------------------------------------------*/
/*!
 * @brief Hash table structure which uses cuckoo hashing.
 *
 * Keys are expected to be strings of characters (char *), not necesarily
 * null-terminated. It uses the Fowler/Noll/Vo (FNV) hash function is used to
 * obtain a 32bit unsigned integer from the character data. The funtion was
 * taken from http://home.comcast.net/~bretm/hash/6.html.
 *
 * The table uses either 3-ary or 4-ary cuckoo hashing (and thus 3 or 4 tables)
 * with stash, according to the number of items provided to ck_create_table()
 * function. The number of table pointers is however set to be the larger value
 * (4) always, so the @a tables array may be statically allocated. Size of one
 * table is always a power of 2 (due to the character of the hash function).
 * The stash has a default size STASH_SIZE, but can be resized if needed.
 * However, the resizing is only done in rehashing process, if the items do not
 * fit into the table and the original stash.
 *
 * Rehashing is done when the stash gets full (actually, last item is always
 * free and is used in the rehashing process as a temporary variable).
 */
typedef struct {
	/*!
	 * @brief Actual number of hash tables used.
	 */
	uint table_count;		// number of hash tables (2, 3 or 4)

	/*!
	 * @brief Exponent of one table size (2^table_size_exp is table size).
	 */
	int table_size_exp;

	/*!
	 * @brief Array of hash tables.
	 */
	ck_hash_table_item **tables[MAX_TABLES];	// hash tables

	/*!
	 * @brief Stash implemented as a dynamic array.
	 */
	da_array stash;

	/*!
	 * @brief Destructor function for the items. Used when destroying the table
	 *        or when deleting individual items.
	 */
	void (*dtor_item)( void *value );

	/*!
	 * @brief Mutex for avoiding multiple insertions / rehashes at once.
	 */
	pthread_mutex_t mtx_table;

	/*!
	 *@brief Flags used for determining which hash functions are used currently.
	 *
	 * Form: 00000xyz.
	 * x - rehash flag
	 * yz - generation (may be 10 = 2, or 01 = 1)
	 *
	 * There are always two sets of hash functions available via the us_hash()
	 * function (see universal-hashing.h). Normally all items in the table are
	 * hashed using one set of functions. However, during rehash, the other set
	 * is used for rehashing. In this case the rehash flag (x) is set, so the
	 * lookup function (ck_find_item()) tries to use both sets of functions when
	 * searching for item.
	 */
	uint8_t generation;		/* 00000xyz x==1 .. rehashing in progress
											yz   .. generation; may be 01 or 10 */
} ck_hash_table;

/*----------------------------------------------------------------------------*/
/* API functions						                                      */
/*----------------------------------------------------------------------------*/
/*!
 * @brief Creates and initializes the hash table structure.
 *
 * @param items Number of items to be hashed to the table. This number
 *              determines the size of the hash table that will be created.
 * @param dtor_item Destructor function for the items that will be stored in the
 *                  hash table. Used in the ck_destroy_table() function.
 *
 * All hash tables are allocated and their items initialized to 0 (NULL).
 * A stash of default size is also created. The @a generation flags are set to
 * 0.
 *
 * @return Pointer to the initialized hash table.
 */
ck_hash_table *ck_create_table( uint items, void (*dtor_item)( void *value ) );

/*----------------------------------------------------------------------------*/
/*!
 * @brief Destroys the whole hash table together with the saved values.
 *
 * @param table Pinter to pointer to the hash table.
 *
 *	Make sure the table and its items are not used anymore when calling this
 *  function.
 *
 *	@todo The item destructor may not be passed on the table creation but on
 *        this function call.
 */
void ck_destroy_table( ck_hash_table **table );

/*----------------------------------------------------------------------------*/
/*!
 * @brief Inserts item into the hash table.
 *
 * @param table Hash table the item should be inserted into.
 * @param key Item's key. It can be any string of octets. The key is not copied
 *            by the function.
 * @param length Length of the key in bytes (octets).
 * @param value Pointer to the actual item to be inserted into the hash table.
 *
 * Insertion starts always by trying to hash the item into the first table. The
 * possible displaced item is then hashed into randomly chosen other table,
 * etc., until a free place is found or a loop occured. A loop occurs when one
 * position in one table is tried more than twice.
 *
 * @note This function does not copy the key. Make sure the key will not be
 *       deallocated elsewhere as this will be done only in the
 *       ck_destroy_table() function.
 * @note This function may trigger rehash of the whole table in case the stash
 *       gets full.
 *
 * @retval 0 No error.
 * @retval -1 Insertion failed. This may occur only when the rehashing fails.
 *            In this case it is necessary to somehow manually force another
 *            rehash as no other rehash would be possible.
 */
int ck_insert_item( ck_hash_table *table, const char *key, size_t length,
                    void *value );

/*----------------------------------------------------------------------------*/
/*!
 * @brief Rehashes the whole table.
 *
 * @param table Hash table to be rehashed.
 *
 * @note While rehashing no item should be inserted as it will result in a
 *       deadlock.
 *
 * @retval 0 No error.
 * @retval -1 Rehashing failed. Some items may have been already moved and the
 *            rehashing flag remains set.
 *
 * @todo This need not to be part of the API!
 */
int ck_rehash( ck_hash_table *table );

/*----------------------------------------------------------------------------*/
/*!
 * @brief Finds item in table.
 *
 * @param table Hash table to search in.
 * @param key Key of the item. It can be an arbitrary string of octets.
 * @param length Length of the key in bytes (octets).
 *
 * @return Pointer to the item if found. NULL otherwise.
 */
const ck_hash_table_item *ck_find_item(
		ck_hash_table *table, const char *key, size_t length );

/*----------------------------------------------------------------------------*/
/*!
 * @brief Dumps the whole hash table to the console.
 */
void ck_dump_table( ck_hash_table *table );

/*----------------------------------------------------------------------------*/

#endif
