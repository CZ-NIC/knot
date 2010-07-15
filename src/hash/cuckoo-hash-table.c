/*!
 * @file cuckoo-hash-table.c
 *
 * @todo Dynamic array for keeping used indices when inserting.
 * @todo Implement d-ary cuckoo hashing / cuckoo hashing with buckets, or both.
 */
/*----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     /* defines uint32_t etc */
#include <assert.h>
#include <pthread.h>

#include <urcu.h>

#include "cuckoo-hash-table.h"
#include "hash-functions.h"
#include "universal-system.h"
#include "common.h"

/*----------------------------------------------------------------------------*/
/* Macros										                              */
/*----------------------------------------------------------------------------*/

#define ERR_WRONG_TABLE log_error("Wrong hash table used.\n")
#define ERR_INF_LOOP log_error("Hashing entered infinite loop.\n")
#define ERR_BITSET log_error("Bitset not correct.\n");
#define ERR_REHASHING_NOT_IMPL \
            log_error("Rehashing needed, but not supported.\n");

#define CK_SIZE_NEAREST 1
#define CK_SIZE_LARGER 2
#define CK_SIZE CK_SIZE_LARGER

#define USED_SIZE 200

#define TABLE_1 0
#define TABLE_2 1
#define TABLE_FIRST TABLE_1
#define TABLE_LAST TABLE_2

#define NEXT_TABLE(table) ((table == TABLE_LAST) ? TABLE_FIRST : table + 1)
#define PREVIOUS_TABLE(table) ((table == TABLE_FIRST) ? TABLE_LAST : table - 1)

#define HASH(key, length, exp, gen, table) \
			us_hash(fnv_hash(key, length, -1), exp, table, gen)
//#define HASH2(key, length, exp, gen, table) \
//            us_hash(fnv_hash(key, length, -1), exp, 1, gen)

static const uint BUFFER_SIZE = 100;

/*----------------------------------------------------------------------------*/

static const uint8_t FLAG_GENERATION1 = 0x1; // 00000001
static const uint8_t FLAG_GENERATION2 = 0x2; // 00000010
static const uint8_t FLAG_GENERATION_BOTH = 0x3; // 00000011
static const uint8_t FLAG_REHASH = 0x4; // 00000100

static inline void CLEAR_FLAGS( uint8_t *flags ) {
    (*flags) &= (uint8_t)0x0;
}

static inline uint8_t GET_GENERATION( uint8_t flags ) {
    return (flags & FLAG_GENERATION_BOTH);
}

static inline int EQUAL_GENERATIONS( uint8_t flags1, uint8_t flags2 ) {
	return (GET_GENERATION(flags1) == GET_GENERATION(flags2));
}

static inline int IS_GENERATION1( uint8_t flags ) {
    return ((flags & FLAG_GENERATION1) != 0);
}

static inline void SET_GENERATION1( uint8_t *flags ) {
    *flags = ((*flags) & ~FLAG_GENERATION2) | FLAG_GENERATION1;
}

static inline int IS_GENERATION2( uint8_t flags ) {
    return ((flags & FLAG_GENERATION2) != 0);
}

static inline void SET_GENERATION2( uint8_t *flags ) {
    *flags = ((*flags) & ~FLAG_GENERATION1) | FLAG_GENERATION2;
}

static inline void SET_GENERATION( uint8_t *flags, uint8_t generation ) {
    *flags = ((*flags) & ~FLAG_GENERATION_BOTH) | generation;
}

static inline uint8_t SET_NEXT_GENERATION( uint8_t *flags ) {
    return ((*flags) ^= FLAG_GENERATION_BOTH);
}

static inline uint8_t NEXT_GENERATION( uint8_t flags ) {
	return ((flags & FLAG_GENERATION_BOTH) ^ FLAG_GENERATION_BOTH);
}

static inline void SET_REHASHING_ON( uint8_t *flags ) {
	 *flags = (*flags | FLAG_REHASH);
}

static inline void SET_REHASHING_OFF( uint8_t *flags ) {
	 *flags = (*flags & ~FLAG_REHASH);
}

static inline int IS_REHASHING( uint8_t flags ) {
	 return ((flags & FLAG_REHASH) != 0);
}

/*----------------------------------------------------------------------------*/
/* Helper functions															  */
/*----------------------------------------------------------------------------*/

uint get_nearest_exp( uint n )
{
	// TODO: optimize
	uint prev = 1;
	uint next = 2;

	while (hashsize(next) < n) {
		prev = next++;
	}

	return ((n - hashsize(prev)) < (hashsize(next) - n))
			? prev
			: next;
}

/*----------------------------------------------------------------------------*/

uint get_larger_exp( uint n )
{
	uint res = 0;
	while (hashsize(++res) < n) {}

	return res;
}

/*----------------------------------------------------------------------------*/
/*!
 * @brief Returns ideal size of one table.
 */
uint get_table_exp( uint items, int size_type )
{
	switch (size_type) {
		case CK_SIZE_LARGER:
			return get_larger_exp(2 * items) - 1;		// optimize
			break;
		case CK_SIZE_NEAREST:
		default:
			return get_nearest_exp(2 * items) - 1;		// optimize
	}
}

/*----------------------------------------------------------------------------*/

static inline void ck_clear_item( ck_hash_table_item **item )
{
	rcu_set_pointer(item, NULL);
}

/*----------------------------------------------------------------------------*/
/*!
 * @brief Insert given contents to the item.
 */
void ck_fill_item( const char *key, size_t key_length, void *value,
                   uint generation, ck_hash_table_item *item )
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
 * @brief Swaps two hash table items.
 */
static inline void ck_swap_items( ck_hash_table_item **item1,
								  ck_hash_table_item **item2 )
{
	// Is this OK? Shouldn't I use some tmp var for saving the value?
	ck_hash_table_item *tmp = rcu_xchg_pointer(item1, *item2);
	rcu_set_pointer(item2, tmp);
}

/*----------------------------------------------------------------------------*/

static inline void ck_put_item( ck_hash_table_item **to,
								ck_hash_table_item *item )
{
	rcu_set_pointer(to, item);
}

/*----------------------------------------------------------------------------*/

uint ck_check_used_twice( uint *used, uint *last, uint32_t hash )
{
    uint i = 0, found = 0;
    while (i <= *last && found < 2) {
        ++i;
        if (used[i] == hash) {
            ++found;
        }
    }

    if (i <= *last && found == 2) {
        ERR_INF_LOOP;
        return -1;
    }
    else {
        *last = i;
        // replace by some check, or resizing a dynamic array
        assert(*last < USED_SIZE);
        used[i] = hash;
        return 0;
    }
}

/*----------------------------------------------------------------------------*/

static inline uint ck_items_match( const ck_hash_table_item* item,
								   const char *key, size_t length )
{
    return (length == item->key_length
			&& (strncmp(item->key, key, length) == 0)) ? 0 : -1;
}

/*----------------------------------------------------------------------------*/

ck_hash_table_item *ck_find_in_buffer( ck_hash_table *table, const char *key,
									   uint length )
{
	uint buf_i = table->buf_i;
	debug_cuckoo("Max buffer offset: %u\n", buf_i);
	uint i = 0;
	while (i < buf_i && table->buffer[i]
		   && ck_items_match(table->buffer[i], key, length))
	{
		++i;
	}

	if (i >= buf_i) {
		return NULL;
	}

	assert(strncmp(table->buffer[i]->key, key, length) == 0);

	return table->buffer[i];
}

/*----------------------------------------------------------------------------*/

ck_hash_table *ck_create_table( uint items, void (*dtor_item)( void *value ) )
{
	ck_hash_table *table = (ck_hash_table *)malloc(sizeof(ck_hash_table));

	if (table == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	// determine ideal size of the table in powers of 2 and save the exponent
	table->table_size_exp = get_table_exp(items, CK_SIZE);
    table->dtor_item = dtor_item;

    log_info("Creating hash table for %u items.\n", items);
    log_info("Exponent: %u ", table->table_size_exp);
    log_info("Table size: %u items, each %u bytes, total %u bytes\n",
		   hashsize(table->table_size_exp), sizeof(ck_hash_table_item *),
		   hashsize(table->table_size_exp) * sizeof(ck_hash_table_item *));

	// create tables
	for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
		table->tables[t] =
			(ck_hash_table_item **)malloc(hashsize(table->table_size_exp)
											* sizeof(ck_hash_table_item *));
		if (table->tables[t] == NULL) {
			ERR_ALLOC_FAILED;
			for (uint i = TABLE_FIRST; i < t; ++i) {
				free(table->tables[i]);
			}
			free(table);
			return NULL;
		}

		// set to 0
		memset(table->tables[t], 0,
			   hashsize(table->table_size_exp) * sizeof(ck_hash_table_item *));
	}

	// create buffer (replace by (generic) variable-length array)
	table->buffer = (ck_hash_table_item **)malloc(
						BUFFER_SIZE	* sizeof(ck_hash_table_item *));

	if (table->buffer == NULL) {
		ERR_ALLOC_FAILED;
		for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
			free(table->tables[t]);
		}
		free(table);
		return NULL;
	}

	// set to 0
	memset(table->buffer, 0, BUFFER_SIZE * sizeof(ck_hash_table_item *));
	table->buf_i = 0;

	// initialize rehash/insert mutex
    pthread_mutex_init(&table->mtx_table, NULL);

	// set the generation to 1 and initialize the universal system
	CLEAR_FLAGS(&table->generation);
	SET_GENERATION1(&table->generation);
	us_initialize();

	return table;
}

/*----------------------------------------------------------------------------*/

void ck_destroy_table( ck_hash_table **table )
{
    pthread_mutex_lock(&(*table)->mtx_table);

	// destroy items in tables
    for (uint i = 0; i < hashsize((*table)->table_size_exp); ++i) {
		for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
			if ((*table)->tables[t][i] != NULL) {
				(*table)->dtor_item((*table)->tables[t][i]->value);
				free((void *)(*table)->tables[t][i]->key);
				free((void *)(*table)->tables[t][i]);
			}
		}
    }

	// destroy items in buffer
    for (uint i = 0; i < (*table)->buf_i; ++i) {
		assert((*table)->buffer[i] != NULL);
		(*table)->dtor_item((*table)->buffer[i]->value);
		free((void *)(*table)->buffer[i]);
    }

	debug_cuckoo("Deleting: table1: %p, table2: %p, buffer: %p, table: %p.\n",
		   (*table)->tables[TABLE_1], (*table)->tables[TABLE_2],
		   (*table)->buffer, *table);

    pthread_mutex_unlock(&(*table)->mtx_table);
    // destroy mutex, assuming that here noone will lock the mutex again
    pthread_mutex_destroy(&(*table)->mtx_table);


	for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
		free((*table)->tables[t]);
	}
    free((*table)->buffer);
    free(*table);

	(*table) = NULL;
}

/*----------------------------------------------------------------------------*/
/*!
 * @retval 0 if successful and no loop occured.
 * @retval 1 if a loop occured and the item was inserted to the @a free place.
 */
int ck_hash_item( ck_hash_table *table, ck_hash_table_item **to_hash,
				  ck_hash_table_item **free, uint8_t generation )
{
	uint32_t used[TABLE_LAST + 1][USED_SIZE];
	uint used_i[TABLE_LAST + 1];
	memset(used_i, 0, (TABLE_LAST + 1) * sizeof(uint));

    // hash until empty cell is encountered or until loop appears

	debug_cuckoo_hash("Hashing key: %s of size %u.\n",
					  (*to_hash)->key, (*to_hash)->key_length);

	int next_table = TABLE_1;

	uint32_t hash = HASH((*to_hash)->key, (*to_hash)->key_length,
						  table->table_size_exp, generation, next_table);

	debug_cuckoo_hash("New hash: %u.\n", hash);

	used[next_table][used_i[next_table]] = hash;
	ck_hash_table_item **next = &table->tables[next_table][hash];
	debug_cuckoo_hash("Item to be moved: %p, place in table: %p\n", *next, next);
	ck_hash_table_item **moving = to_hash;

	next_table = NEXT_TABLE(next_table);
    int loop = 0;

	while (*next != NULL) {
		debug_cuckoo_hash("Swapping items. To hash: %p and Moving: %p\n",
						  to_hash, moving);

		ck_swap_items(to_hash, moving); // first time it's unnecessary
		debug_cuckoo_hash("After swap. To hash: %p, Moving: %p\n",
						  to_hash, moving);

        // set the generation of the inserted item to the next generation
		SET_GENERATION(&(*moving)->timestamp, generation);

        moving = next;

		debug_cuckoo_hash("Moving item from table %u, key: %s, hash %u",
			   PREVIOUS_TABLE(next_table) + 1, (*moving)->key, hash);

        // if the 'next' item is from the old generation, start from table 1
		if (generation != table->generation
			&& EQUAL_GENERATIONS((*next)->timestamp, table->generation)) {
			next_table = TABLE_1;
		}

		hash = HASH((*next)->key, (*next)->key_length,
					 table->table_size_exp, generation, next_table);
		next = &table->tables[next_table][hash];

		debug_cuckoo_hash(" to table 1, hash %u, item: %p, place: %p\n",
						  hash, *next, next);
		if ((*next) != NULL) {
			debug_cuckoo_hash("Table 1, hash: %u, key: %s\n", hash,
							  (*next)->key);
		}

		// check if this cell wasn't already used in this item's hashing
		if (ck_check_used_twice(used[next_table], &used_i[next_table], hash)
				!= 0) {
			next = free;
			loop = -1;
			break;
		}

        next_table = NEXT_TABLE(next_table);
    }

	debug_cuckoo_hash("Putting pointer %p (*moving) to item %p (next).\n",
					  *moving, next);
	ck_put_item(next, *moving);
    // set the new generation for the inserted item
	SET_GENERATION(&(*next)->timestamp, generation);
	debug_cuckoo_hash("Putting pointer %p (*old) to item %p (moving).\n",
					  *to_hash, moving);
	ck_put_item(moving, *to_hash);
	// set the new generation for the inserted item
	SET_GENERATION(&(*moving)->timestamp, generation);

	return loop;
}

/*----------------------------------------------------------------------------*/

int ck_insert_item( ck_hash_table *table, const char *key,
					size_t length, void *value )
{
	// lock mutex to avoid write conflicts
	pthread_mutex_lock(&table->mtx_table);

	debug_cuckoo_hash("Inserting item with key: %s.\n", key);
	debug_cuckoo_hash_hex(key, length);

	// create item structure and fill in the given data, key will not be copied!
	ck_hash_table_item *new_item =
			(ck_hash_table_item *)malloc((sizeof(ck_hash_table_item)));
	ck_fill_item(key, length, value, GET_GENERATION(table->generation),
				 new_item);

	// check if this works (using the same pointer for 'old' and 'free')
	assert(table->buf_i + 1 < BUFFER_SIZE);
	if (ck_hash_item(table, &new_item, &table->buffer[table->buf_i],
					 table->generation) != 0) {
		printf("Item with key %*s inserted into the buffer.\n",
			   table->buffer[table->buf_i]->key_length,
			   table->buffer[table->buf_i]->key);

		// loop occured, the item is already at its new place in the buffer,
		// so just increment the index and check if rehash is not needed
		++table->buf_i;

		// if only one place left, rehash (this place is used in rehashing)
		if (table->buf_i + 1 == BUFFER_SIZE) {
			int res = ck_rehash(table);
			if (res != 0) {
				printf("Rehashing not successful, rehash flag: %hu\n",
					   IS_REHASHING(table->generation));
			}
			pthread_mutex_unlock(&table->mtx_table);
			return res;
		}
	}

	pthread_mutex_unlock(&table->mtx_table);
	return 0;
}

/*----------------------------------------------------------------------------*/

void ck_rollback_rehash( ck_hash_table *table )
{
	// set old generation in tables
	for (int i = 0; i < hashsize(table->table_size_exp); ++i) {
		// no need for locking - timestamp is not used in lookup
		// and two paralel insertions (and thus rehashings) are impossible
		for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
			if (table->tables[t][i] != NULL) {
				SET_GENERATION(&table->tables[t][i]->timestamp,
							   table->generation);
			}
		}
	}

	// set old generation in buffer
	for (int i = 0; i < BUFFER_SIZE; ++i) {
		if (table->buffer[i] != NULL) {
			SET_GENERATION(&table->buffer[i]->timestamp, table->generation);
		}
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * If not successful, the rehashing flag should still be set after returning.
 */
int ck_rehash( ck_hash_table *table )
{
	debug_cuckoo_rehash("Rehashing items in table.\n");
	SET_REHASHING_ON(&table->generation);

    // we already have functions for the next generation, begin rehashing
	// we wil use the last item in the buffer as free cell for hashing
    assert(table->buf_i + 1 <= BUFFER_SIZE);
	//ck_hash_table_item **old = &table->buffer[table->buf_i];
	ck_hash_table_item *old = (ck_hash_table_item *)
							  (malloc(sizeof(ck_hash_table_item)));

	debug_cuckoo_rehash("Place in buffer used for rehashing: %u, %p\n",
						table->buf_i, old);

	// rehash items from buffer, starting from the last old item
	int buf_i = table->buf_i - 1;
	while (buf_i >= 0) {

		// if item's generation is the new generation, skip
		if (table->buffer[buf_i] == NULL
			|| !(EQUAL_GENERATIONS(table->buffer[buf_i]->timestamp,
								   table->generation))) {

			debug_cuckoo_rehash("Skipping item.\n");

			--buf_i;
			continue;
		}

		debug_cuckoo_rehash("Rehashing item from buffer position %u, key "
			"(length %u): %*s, generation: %hu, table generation: %hu.\n",
			buf_i, table->buffer[buf_i]->key_length,
			(int)table->buffer[buf_i]->key_length,
			table->buffer[buf_i]->key,
			GET_GENERATION(table->buffer[buf_i]->timestamp),
			GET_GENERATION(table->generation));

		// otherwise copy the item for rehashing
		ck_put_item(&old, table->buffer[buf_i]);
		// clear the place so that this item will not get rehashed again
		ck_clear_item(&table->buffer[buf_i]);

		assert(table->buffer[buf_i] == NULL);

		// and start rehashing
		if (ck_hash_item(table, &old, &table->buffer[buf_i],
						 NEXT_GENERATION(table->generation))
			== -1) {
			ERR_INF_LOOP;
			// loop occured
			ck_rollback_rehash(table);

			printf("Item which caused the infinite loop: %*s (pointer: %p).\n",
				  old->key_length, old->key, &old);
			printf("Item inserted in the free place: %*s (pointer: %p).\n",
				  table->buffer[buf_i]->key_length,
				  table->buffer[buf_i]->key, &table->buffer[buf_i]);
			printf("Last index in buffer: %u, inserted item's index: %u\n",
				   table->buf_i, buf_i);

			// clear the 'old' item
			ck_clear_item(&old);

			assert(table->buf_i + 1 < BUFFER_SIZE);
			assert(table->buffer[table->buf_i - 1] != NULL);
			assert(table->buffer[table->buf_i] == NULL);

			return -1;
		}

		// clear the 'old' item
		ck_clear_item(&old);
		// decrement the index
		--buf_i;
		// rehash successful, so there is one item less in the buffer
		--table->buf_i;
	}

	uint i = 0;
	while (i < table->buf_i) {
		assert(table->buffer[i] != NULL);
		++i;
	}
	assert(table->buffer[table->buf_i] == NULL);

	// rehash items from hash tables
	for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
		debug_cuckoo_rehash("Rehashing items from table %d.\n", t + 1);
		uint rehashed = 0;

		while (rehashed < hashsize(table->table_size_exp)) {

			// if item's generation is the new generation, skip
			if (table->tables[t][rehashed] == NULL
				|| !(EQUAL_GENERATIONS(table->tables[t][rehashed]->timestamp,
									   table->generation))) {

				debug_cuckoo_rehash("Skipping item.\n");

				++rehashed;
				continue;
			}

			debug_cuckoo_rehash("Rehashing item with hash %u, key (length %u): "
					"%*s, generation: %hu, table generation: %hu.\n", rehashed,
				   table->tables[t][rehashed]->key_length,
				   (int)(table->tables[t][rehashed]->key_length),
				   table->tables[t][rehashed]->key,
				   GET_GENERATION(table->tables[t][rehashed]->timestamp),
				   GET_GENERATION(table->generation));

			// otherwise copy the item for rehashing
			ck_put_item(&old, table->tables[t][rehashed]);
			// clear the place so that this item will not get rehashed again
			ck_clear_item(&table->tables[t][rehashed]);

			debug_cuckoo_rehash("Table generation: %hu, next generation: %hu.\n",
								GET_GENERATION(table->generation),
								NEXT_GENERATION(table->generation));

			// and start rehashing
			assert(&old != &table->buffer[table->buf_i]);
			if (ck_hash_item(table, &old, &table->buffer[table->buf_i],
							 NEXT_GENERATION(table->generation))
				== -1) {
				ERR_INF_LOOP;
				// loop occured
				ck_rollback_rehash(table);

				printf("Item which caused the infinite loop: %*s.\n",
					  old->key_length, old->key);
				printf("Item inserted in the free place: %*s.\n",
					  table->buffer[table->buf_i]->key_length,
					  table->buffer[table->buf_i]->key);
				printf("Last index in buffer: %u, inserted item's index: %u\n",
					   table->buf_i + 1, table->buf_i);
				printf("Rehashing flag: %hu\n", IS_REHASHING(table->generation));

				// the item was put into the buffer, so increment the buffer index
				++table->buf_i;

				assert(table->buf_i + 1 < BUFFER_SIZE);
				assert(table->buffer[table->buf_i - 1] != NULL);
				assert(table->buffer[table->buf_i] == NULL);

				// clear the 'old' item
				ck_clear_item(&old);

				return -1;
			}

			++rehashed;
		}
	}

    // rehashing completed, switch generation of the table
    SET_NEXT_GENERATION(&table->generation);
	SET_REHASHING_OFF(&table->generation);
    return 0;
}

/*----------------------------------------------------------------------------*/

const ck_hash_table_item *ck_find_gen( ck_hash_table *table, const char *key,
										size_t length, uint8_t generation )
{
    uint32_t hash;

	// check hash tables
	for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
		hash = HASH(key, length, table->table_size_exp, generation, t);

		debug_cuckoo("Hash: %u, key: %s\n", hash, key);
		debug_cuckoo("Table %d, hash: %u, item: %p\n", t + 1, hash,
					 table->tables[t][hash]);
		if (table->tables[t][hash] != NULL) {
			debug_cuckoo("Table %d, key: %s, value: %p, key length: %u\n",
				t + 1, table->tables[t][hash]->key, table->tables[t][hash]->value,
				table->tables[t][hash]->key_length);
		}

		if (table->tables[t][hash]
			&& (ck_items_match(table->tables[t][hash], key, length) == 0)) {
			// found
			return table->tables[t][hash];
		}
	}

	// try to find in buffer
	debug_cuckoo("Searching in buffer...\n");

	ck_hash_table_item *found =
		ck_find_in_buffer(table, key, length);

    debug_cuckoo("Found pointer: %p\n", found);
	if (found != NULL) {
		debug_cuckoo("Buffer, key: %s, value: %p, key length: %u\n",
		   found->key, found->value, found->key_length);
	}

	// ck_find_in_buffer returns NULL if not found, otherwise pointer to item
	return found;
}

/*----------------------------------------------------------------------------*/

const ck_hash_table_item *ck_find_item( ck_hash_table *table, const char *key,
										size_t length )
{
	// get the generation of the table so that we use the same value
	uint8_t generation = table->generation;

	// find item using the table generation's hash functions
	const ck_hash_table_item *found = ck_find_gen(table, key, length,
											GET_GENERATION(generation));
	// if rehashing is in progress, try the next generation's functions
	if (!found && IS_REHASHING(generation)) {
		found = ck_find_gen(table, key, length, NEXT_GENERATION(generation));
	}

	return found;
}

/*----------------------------------------------------------------------------*/

void ck_dump_table( ck_hash_table *table )
{
	uint i;

	debug_cuckoo("----------------------------------------------\n");
	debug_cuckoo("Hash table dump:\n\n");
	debug_cuckoo("Size of each table: %u\n\n", hashsize(table->table_size_exp));

	for (uint t = TABLE_FIRST; t <= TABLE_LAST; ++t) {
		debug_cuckoo("Table %d:\n", t + 1);

		for (i = 0; i < hashsize(table->table_size_exp); i++) {
			debug_cuckoo("Hash: %u, Key: %*s, Value: %p.\n", i,
						 table->tables[t][i]->key_length,
						 table->tables[t][i]->key, table->tables[t][i]->value);
		}
	}

	debug_cuckoo("Buffer:\n");
	for (i = 0; i < table->buf_i; ++i) {
		debug_cuckoo("Index: %u, Key: %*s Value: %p.\n", i,
					 table->buffer[i]->key_length, table->buffer[i]->key,
					 table->buffer[i]->value);
	}

	debug_cuckoo("\n");
}
