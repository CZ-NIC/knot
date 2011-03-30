#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     /* defines uint32_t etc */
#include <assert.h>
#include <pthread.h>

#include <urcu.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/debug.h"
#include "dnslib/hash/cuckoo-hash-table.h"
#include "dnslib/hash/hash-functions.h"
#include "common/dynamic-array.h"

/*----------------------------------------------------------------------------*/
/* Macros and inline functions                                                */
/*----------------------------------------------------------------------------*/

#define CK_SIZE_NEAREST 1
#define CK_SIZE_LARGER 2
#define CK_SIZE CK_SIZE_LARGER

#define RELOCATIONS_DEFAULT 200
#define RELOCATIONS_MAX 1000

#define TABLE_FIRST 0
#define TABLE_LAST(count) (count - 1)
// random walk
#define NEXT_TABLE(table, count) (rand() % count)

#define HASH(system, key, length, exp, gen, table) \
	us_hash(system, fnv_hash(key, length, -1), exp, table, gen)

#define STASH_ITEMS(stash) ((ck_hash_table_item_t **)(da_get_items(stash)))

static const float SIZE_RATIO_2 = 2;
static const float SIZE_RATIO_3 = 1.15;
static const float SIZE_RATIO_4 = 1.08;

/*----------------------------------------------------------------------------*/

static const uint8_t FLAG_GENERATION1     = 0x1; // 00000001
static const uint8_t FLAG_GENERATION2     = 0x2; // 00000010
static const uint8_t FLAG_GENERATION_BOTH = 0x3; // 00000011
static const uint8_t FLAG_REHASH          = 0x4; // 00000100

static inline void CLEAR_FLAGS(uint8_t *flags)
{
	*flags = (uint8_t)0x0;
}

static inline uint8_t GET_GENERATION(uint8_t flags)
{
	return (flags & FLAG_GENERATION_BOTH);
}

static inline int EQUAL_GENERATIONS(uint8_t flags1, uint8_t flags2)
{
	return (GET_GENERATION(flags1) == GET_GENERATION(flags2));
}

static inline int IS_GENERATION1(uint8_t flags)
{
	return ((flags & FLAG_GENERATION1) != 0);
}

static inline void SET_GENERATION1(uint8_t *flags)
{
	*flags = ((*flags) & ~FLAG_GENERATION2) | FLAG_GENERATION1;
}

static inline int IS_GENERATION2(uint8_t flags)
{
	return ((flags & FLAG_GENERATION2) != 0);
}

static inline void SET_GENERATION2(uint8_t *flags)
{
	*flags = ((*flags) & ~FLAG_GENERATION1) | FLAG_GENERATION2;
}

static inline void SET_GENERATION(uint8_t *flags, uint8_t generation)
{
	*flags = ((*flags) & ~FLAG_GENERATION_BOTH) | generation;
}

static inline uint8_t SET_NEXT_GENERATION(uint8_t *flags)
{
	return ((*flags) ^= FLAG_GENERATION_BOTH);
}

static inline uint8_t NEXT_GENERATION(uint8_t flags)
{
	return ((flags & FLAG_GENERATION_BOTH) ^ FLAG_GENERATION_BOTH);
}

static inline void SET_REHASHING_ON(uint8_t *flags)
{
	*flags = (*flags | FLAG_REHASH);
}

static inline void SET_REHASHING_OFF(uint8_t *flags)
{
	*flags = (*flags & ~FLAG_REHASH);
}

static inline int IS_REHASHING(uint8_t flags)
{
	return ((flags & FLAG_REHASH) != 0);
}

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Returns the exponent of the nearest power of two.
 */
//static uint get_nearest_exp(uint n)
//{
//	// TODO: optimize
//	uint prev = 1;
//	uint next = 2;

//	while (hashsize(next) < n) {
//		prev = next++;
//	}

//	return ((n - hashsize(prev)) < (hashsize(next) - n))
//	       ? prev
//	       : next;
//}

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
 * \brief Returns ideal size of one table.
 */
static uint get_table_exp_and_count(uint items, uint *table_count)
{
	// considering only 3 or 4 tables
	uint exp3 = get_larger_exp((items * SIZE_RATIO_3) / 3);
	uint exp4 = get_larger_exp(items * SIZE_RATIO_4) - 2;

	debug_ck("Determining ideal table size...\n");
	debug_ck("\tNumber of items: %u\n", items);
	debug_ck("\tThree tables: size of one table: %u, total size: %u\n",
	         hashsize(exp3), 3 * hashsize(exp3));
	debug_ck("\tFour tables: size of one table: %u, total size: %u\n",
	         hashsize(exp4), 4 * hashsize(exp4));

	// we need exponent at least 1 (this is quite ugly..)
	if (exp3 == 0) {
		exp3 = 1;
	}
	if (exp4 == 0) {
		exp4 = 1;
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
 * \brief Clears the given item by assigning a NULL pointer to it.
 */
static inline void ck_clear_item(ck_hash_table_item_t **item)
{
	rcu_set_pointer(item, NULL);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Insert given contents to the item.
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
	// Is this OK? Shouldn't I use some tmp var for saving the value?
	ck_hash_table_item_t *tmp = rcu_xchg_pointer(item1, *item2);
	rcu_set_pointer(item2, tmp);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets the \a item pointer to the \a to pointer.
 */
static inline void ck_put_item(ck_hash_table_item_t **to,
                               ck_hash_table_item_t *item)
{
	rcu_set_pointer(to, item);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if the current hash was already use twice.
 *
 * If yes, it means we entered a loop in the hashing process, so we must stop.
 * Otherwise it remembers that we used the hash.
 *
 * \note According to Kirsch, et al. a check that at most one hash was used
 *       twice should be sufficient. We will retain our version for now.
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
		debug_ck_hash("Hashing entered infinite loop.\n");
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
 */
static inline uint ck_items_match(const ck_hash_table_item_t *item,
                                  const char *key, size_t length)
{
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
	while ((*table) == (next = rand() % table_count)) {}
	*table = next;
}

/*----------------------------------------------------------------------------*/

static ck_hash_table_item_t **ck_find_in_stash(const ck_hash_table_t *table,
                                               const char *key, uint length)
{
	ck_stash_item_t *item = table->stash2;
	while (item != NULL) {
		debug_ck("Comparing item in stash (key: %.*s (size %zu))"
		         "with searched item (key %.*s (size %u)).\n",
		         (int)item->item->key_length, item->item->key,
		         item->item->key_length, (int)length, key, length);
		if (ck_items_match(item->item, key, length)) {
			return &item->item;
		}
		item = item->next;
	}

	return NULL;

//	//assert(table->stash_i == da_get_count(&table->stash));
//	uint stash_i = da_get_count(&table->stash);
//	debug_ck("Items in stash: %u\n", stash_i);
//	uint i = 0;
//	while (i < stash_i
//	       && (((ck_hash_table_item_t **)(da_get_items(&table->stash)))[i]
//		   != NULL)
//	       && ck_items_match(((ck_hash_table_item_t **)
//	                           (da_get_items(&table->stash)))[i],
//				 key, length)) {
//		++i;
//	}

//	if (i >= stash_i) {
//		return NULL;
//	}

//	assert(strncmp(((ck_hash_table_item_t **)
//	             (da_get_items(&table->stash)))[i]->key, key, length) == 0);

//	return &((ck_hash_table_item_t **)(da_get_items(&table->stash)))[i];
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to find item with given key using hash functions from the given
 *        generation.
 */
static ck_hash_table_item_t **ck_find_gen(const ck_hash_table_t *table,
                                          const char *key,
                                          size_t length, uint8_t generation)
{
	uint32_t hash;
	debug_ck("Finding item in generation: %u\n", generation);

	// check hash tables
	for (uint t = TABLE_FIRST; t <= TABLE_LAST(table->table_count); ++t) {
		hash = HASH(&table->hash_system, key, length,
		            table->table_size_exp, generation, t);

		debug_ck("Hash: %u, key: %.*s\n", hash, (int)length, key);
		debug_ck("Table %d, hash: %u, item: %p\n", t + 1, hash,
		         table->tables[t][hash]);
		if (table->tables[t][hash] != NULL) {
			debug_ck("Table %u, key: %.*s, value: %p, key "
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
	debug_ck("Searching in stash...\n");

	ck_hash_table_item_t **found =
	        ck_find_in_stash(table, key, length);

	debug_ck("Found pointer: %p\n", found);
	if (found != NULL) {
		debug_ck("Stash, key: %.*s, value: %p, key length: %zu\n",
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

	debug_ck_hash("Hashing key: %.*s of size %zu.\n",
	              (int)(*to_hash)->key_length, (*to_hash)->key,
	              (*to_hash)->key_length);

	uint next_table = TABLE_FIRST;

	uint32_t hash = HASH(&table->hash_system, (*to_hash)->key,
	                     (*to_hash)->key_length, table->table_size_exp,
	                     generation, next_table);

	debug_ck_hash("New hash: %u.\n", hash);
	assert(hash < hashsize(table->table_size_exp));

	((uint *)da_get_items(&used[next_table]))
	[da_get_count(&used[next_table])] = hash;
	ck_hash_table_item_t **next = &table->tables[next_table][hash];
	debug_ck_hash("Item to be moved: %p, place in table: %p\n",
	              *next, next);
	ck_hash_table_item_t **moving = to_hash;

	int loop = 0;

	while (*next != NULL) {
		debug_ck_hash("Swapping items to hash: %p and Moving: %p\n",
		              to_hash, moving);
		ck_swap_items(to_hash, moving); // first time it's unnecessary

		// set the generation of the inserted item to the next
		SET_GENERATION(&(*moving)->timestamp, generation);

		moving = next;

		debug_ck_hash("Moving item from table %u, key: %.*s, hash %u ",
		              next_table + 1, (int)(*moving)->key_length,
		              (*moving)->key, hash);

		// if rehashing and the 'next' item is from the old generation,
		// start from table 1
		if (generation != table->generation &&
		    EQUAL_GENERATIONS((*next)->timestamp, table->generation)) {
			next_table = TABLE_FIRST;
		} else {
			ck_next_table(&next_table, table->table_count);
		}

		hash = HASH(&table->hash_system, (*next)->key,
		            (*next)->key_length, table->table_size_exp,
		            generation, next_table);

		next = &table->tables[next_table][hash];

		debug_ck_hash("to table %u, hash %u, item: %p, place: %p\n",
		              next_table + 1, hash, *next, next);

		if ((*next) != NULL) {
			debug_ck_hash("Table %u, hash: %u, key: %.*s\n",
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

	debug_ck_hash("Putting pointer %p (*moving) to item %p (next).\n",
	              *moving, next);

	ck_put_item(next, *moving);
	// set the new generation for the inserted item
	SET_GENERATION(&(*next)->timestamp, generation);
	debug_ck_hash("Putting pointer %p (*old) to item %p (moving).\n",
	              *to_hash, moving);

	ck_put_item(moving, *to_hash);
	// set the new generation for the inserted item
	SET_GENERATION(&(*moving)->timestamp, generation);

	for (uint i = 0; i < table->table_count; ++i) {
		da_destroy(&used[i]);
	}

	return loop;
}

/*----------------------------------------------------------------------------*/

//static void ck_rollback_rehash(ck_hash_table_t *table)
//{
//	// set old generation in tables
//	for (int i = 0; i < hashsize(table->table_size_exp); ++i) {
//		// no need for locking - timestamp is not used in lookup
//		// and two paralel insertions (and thus rehashings) are
//		// impossible
//		for (uint t = TABLE_FIRST;
//		     t <= TABLE_LAST(table->table_count); ++t) {
//			if (table->tables[t][i] != NULL) {
//				SET_GENERATION(&table->tables[t][i]->timestamp,
//				               table->generation);
//			}
//		}
//	}

//	// set old generation in stash
////	for (int i = 0; i < STASH_SIZE; ++i) {
////		if (((ck_hash_table_item_t **)(da_get_items(&table->stash)))[i]
////		     != NULL) {
////			SET_GENERATION(&((ck_hash_table_item_t **)
////			           (da_get_items(&table->stash)))[i]->timestamp,
////			           table->generation);
////		}
////	}
//	ck_stash_item_t *item = table->stash2;
//	while (item != NULL) {
//		assert(item->item != NULL);
//		SET_GENERATION(&item->item->timestamp, table->generation);
//	}
//}

/*----------------------------------------------------------------------------*/

int ck_add_to_stash(ck_hash_table_t *table, ck_hash_table_item_t *item)
{
	ck_stash_item_t *new_item
		= (ck_stash_item_t *)malloc(sizeof(ck_stash_item_t));
	if (new_item == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	new_item->item = item;
	new_item->next = table->stash2;
	rcu_set_pointer(&table->stash2, new_item);

	debug_ck_hash("First item in stash (now inserted): key: %.*s (size %zu),"
	              " value: %p\n", (int)table->stash2->item->key_length,
	              table->stash2->item->key, table->stash2->item->key_length,
	              table->stash2->item->value);
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

	// determine ideal size of one table in powers of 2 and save the
	// exponent
	table->table_size_exp = get_table_exp_and_count(items,
							&table->table_count);

	debug_ck("Creating hash table for %u items.\n", items);
	debug_ck("Exponent: %u, number of tables: %u\n ",
		 table->table_size_exp, table->table_count);
	debug_ck("Table size: %u items, each %zu bytes, total %zu bytes\n",
	         hashsize(table->table_size_exp),
	         sizeof(ck_hash_table_item_t *),
	         hashsize(table->table_size_exp)
	           * sizeof(ck_hash_table_item_t *));

	// create tables
	for (uint t = TABLE_FIRST; t <= TABLE_LAST(table->table_count); ++t) {
		debug_ck("Creating table %u...\n", t);
		table->tables[t] =
		        (ck_hash_table_item_t **)malloc(
		                        hashsize(table->table_size_exp)
		                        * sizeof(ck_hash_table_item_t *));
		if (table->tables[t] == NULL) {
			ERR_ALLOC_FAILED;
			for (uint i = TABLE_FIRST; i < t; ++i) {
				free(table->tables[i]);
			}
			free(table);
			return NULL;
		}

		// set to 0
		memset(table->tables[t], 0, hashsize(table->table_size_exp)
		                             * sizeof(ck_hash_table_item_t *));
	}

	// create stash (replace by (generic) variable-length array)
//	if (da_initialize(&table->stash, STASH_SIZE,
//	                  sizeof(ck_hash_table_item_t *)) != 0) {
//		for (uint t = TABLE_FIRST;
//		     t <= TABLE_LAST(table->table_count); ++t) {
//			free(table->tables[t]);
//		}
//		free(table);
//		return NULL;
//	}

	table->stash2 = NULL;

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
		for (uint t = TABLE_FIRST;
		     t <= TABLE_LAST((*table)->table_count); ++t) {
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
	ck_stash_item_t *item = (*table)->stash2;
	while (item != NULL) {
		// disconnect the item
		(*table)->stash2 = item->next;
		assert(item->item != NULL);

		if (dtor_value) {
			dtor_value(item->item->value);
		}
		if (delete_key) {
			free((void *)item->item->key);
		}

		free((void *)item->item);
		free(item);
		item = (*table)->stash2;
	}

	// deallocate tables
	for (uint t = TABLE_FIRST;
	     t <= TABLE_LAST((*table)->table_count); ++t) {
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

/*----------------------------------------------------------------------------*/
#ifdef CT_TEST_REHASH
//int ck_rehash(ck_hash_table_t *table);

/*----------------------------------------------------------------------------*/
#else
//static int ck_rehash(ck_hash_table_t *table);

/*----------------------------------------------------------------------------*/
#endif

int ck_insert_item(ck_hash_table_t *table, const char *key,
                   size_t length, void *value)
{
	// lock mutex to avoid write conflicts
	pthread_mutex_lock(&table->mtx_table);

	assert(value != NULL);

	debug_ck_hash("Inserting item with key: %.*s.\n", (int)length, key);
	debug_ck_hash_hex(key, length);
	debug_ck_hash("\n");

	// create item structure and fill in the given data, key won't be copied
	ck_hash_table_item_t *new_item =
	        (ck_hash_table_item_t *)malloc((sizeof(ck_hash_table_item_t)));
	ck_fill_item(key, length, value, GET_GENERATION(table->generation),
	             new_item);

	// there should be at least 2 free places
	//assert(da_try_reserve(&table->stash, 2) == 0);
	//da_reserve(&table->stash, 1);
	ck_hash_table_item_t *free_place = NULL;
	if (ck_hash_item(table, &new_item, &free_place,
	                 table->generation) != 0) {

		debug_ck("Adding item with key %.*s to stash.\n",
		         (int)free_place->key_length, free_place->key);

		// maybe some limit on the stash and rehash if full
		if (ck_add_to_stash(table, free_place) != 0) {
			debug_ck_hash("Could not add item to stash!!\n");
			assert(0);
		}

//		debug_ck_hash("Item with key %.*s inserted into buffer.\n",
//		              STASH_ITEMS(&table->stash)
//		                [da_get_count(&table->stash)]->key_length,
//		              STASH_ITEMS(&table->stash)
//		                [da_get_count(&table->stash)]->key);

		// loop occured, the item is already at its new place in the
		// buffer, so just increment the index and check if rehash is
		// not needed
//		da_occupy(&table->stash, 1);

		// if only one place left, rehash (this place is used in
		// rehashing)
//		if (da_try_reserve(&table->stash, 2) != 0) {
//			debug_ck_hash("Rehash...\n");
//			int res = ck_rehash(table);
//			if (res != 0) {
//				debug_ck_hash("Rehashing not successful, "
//				              "rehash flag: %hu\n",
//				              IS_REHASHING(table->generation));
//				assert(0);
//			}
//			pthread_mutex_unlock(&table->mtx_table);
//			return res;
//		}
	}

	pthread_mutex_unlock(&table->mtx_table);
	return 0;
}

/*----------------------------------------------------------------------------*/

const ck_hash_table_item_t *ck_find_item(const ck_hash_table_t *table,
                                         const char *key, size_t length)
{
	debug_ck("ck_find_item(), key: %.*s, size: %zu\n",
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

int ck_remove_item(const ck_hash_table_t *table, const char *key, size_t length,
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
//	debug_ck_rehash("Rehashing items in table.\n");
//	SET_REHASHING_ON(&table->generation);

//	// we already have functions for the next generation, begin rehashing
//	// we wil use the last item in the buffer as free cell for hashing
//	assert(da_try_reserve(&table->stash, 1) == 0);
//	ck_hash_table_item_t *old = (ck_hash_table_item_t *)
//	                          (malloc(sizeof(ck_hash_table_item_t)));

//	do {
//		debug_ck_hash("Rehash!\n");

//		if (da_get_count(&table->stash) > STASH_SIZE) {
//			debug_ck_hash("STASH RESIZED!!! (new stash size: %d)\n",
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
//				debug_ck_rehash("Skipping item.\n");
//				--stash_i;
//				continue;
//			}

//			debug_ck_rehash("Rehashing item from buffer position %u"
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
//				debug_ck_hash("Hashing entered a loop.\n");

//				debug_ck_rehash("Item with key %.*s inserted "
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
//					debug_ck_hash("Failed to rehash items "
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
//		debug_ck_hash("OK\n");
//		assert(da_try_reserve(&table->stash, 1) == 0);
//		assert(STASH_ITEMS(&table->stash)[da_get_count(&table->stash)]
//		       == NULL);

//		// rehash items from hash tables
//		for (uint t = TABLE_FIRST;
//		     t <= TABLE_LAST(table->table_count); ++t) {
//			debug_ck_rehash("Rehashing items from table %d.\n",
//			                t + 1);
//			uint rehashed = 0;

//			while (rehashed < hashsize(table->table_size_exp)) {

//				// if item's generation is the new generation,
//				// skip
//				if (table->tables[t][rehashed] == NULL
//				    || !(EQUAL_GENERATIONS(
//				          table->tables[t][rehashed]->timestamp,
//				          table->generation))) {
//					debug_ck_rehash("Skipping item.\n");
//					++rehashed;
//					continue;
//				}

//				debug_ck_rehash("Rehashing item with hash %u, "
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

//				debug_ck_rehash("Table generation: %hu, next "
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
//					debug_ck_hash("Hashing entered a loop."
//						      "\n");
//					debug_ck_rehash("Item with key %.*s "
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
//						debug_ck_hash("Failed to rehash"
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

//		debug_ck_rehash("Old table generation: %u\n",
//		                GET_GENERATION(table->generation));
//		// rehashing completed, switch generation of the table
//		SET_NEXT_GENERATION(&table->generation);
//		debug_ck_rehash("New table generation: %u\n",
//		                GET_GENERATION(table->generation));
//		// generate new hash functions for the old generation
//		debug_ck_rehash("Generating coeficients for generation: %u\n",
//		                NEXT_GENERATION(table->generation));
//		us_next(NEXT_GENERATION(table->generation));

//		// repeat rehashing while there are more items in the stash than
//		// its initial size
//		if (da_get_count(&table->stash) > STASH_SIZE) {
//			debug_ck_rehash("Rehashing again!\n");
//		}
//	} while (da_get_count(&table->stash) > STASH_SIZE);

//	SET_REHASHING_OFF(&table->generation);

//	return 0;
//}

/*----------------------------------------------------------------------------*/

void ck_dump_table(const ck_hash_table_t *table)
{
#ifdef CUCKOO_DEBUG
	uint i;
	debug_ck("----------------------------------------------\n");
	debug_ck("Hash table dump:\n\n");
	debug_ck("Size of each table: %u\n\n", hashsize(table->table_size_exp));

	for (uint t = TABLE_FIRST; t <= TABLE_LAST(table->table_count); ++t) {
		debug_ck("Table %d:\n", t + 1);

		for (i = 0; i < hashsize(table->table_size_exp); i++) {
			debug_ck("Hash: %u, Key: %.*s, Value: %p.\n", i,
			         (int)(table->tables[t])[i]->key_length,
			         (table->tables[t])[i]->key,
			         (table->tables[t])[i]->value);
		}
	}

	debug_ck("Stash:\n");
//	for (i = 0; i < da_get_count(&table->stash); ++i) {
//		debug_ck("Index: %u, Key: %.*s Value: %p.\n", i,
//		         ((ck_hash_table_item_t **)
//		             da_get_items(&table->stash))[i]->key_length,
//		         ((ck_hash_table_item_t **)
//		             da_get_items(&table->stash))[i]->key,
//		         ((ck_hash_table_item_t **)
//		             da_get_items(&table->stash))[i]->value);
//	}
	ck_stash_item_t *item = table->stash2;
	while (item != NULL) {
		debug_ck("Hash: %u, Key: %.*s, Value: %p.\n", i,
			 (int)item->item->key_length, item->item->key,
			 item->item->value);
		item = item->next;
	}

	debug_ck("\n");
#endif
}
