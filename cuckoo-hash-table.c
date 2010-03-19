
/**
 * @todo Dynamic array for keeping used indices when inserting.
 * @todo Implement d-ary cuckoo hashing / cuckoo hashing with buckets, or both.
 * @todo Implement rehashing.
 * @todo Remove the 'collisions' parameter from ck_insert_item().
 * @todo Use only one type of function (fnv or jenkins or some other) and
 *       different coeficients.
 * @todo Optimize the table for space (d-ary hashing will help).
 *
 * @todo One problem with rehashing (and possibly hashing) is because if the
 *       item rehashing process tries to insert to the position where the
 *       iserted item was put, it ends as it detects 'infinite loop'.
 *       However it would be probably better to check the second place for the
 *       item before concluding so.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     /* defines uint32_t etc */
#include <assert.h>
#include <pthread.h>

#include "cuckoo-hash-table.h"
#include "hash-functions.h"
#include "bitset.h"
#include "universal-system.h"

//#define CUCKOO_DEBUG
#define CUCKOO_DEBUG_REHASH

#if defined(CUCKOO_DEBUG) && !defined(CUCKOO_DEBUG_REHASH)
    #define CUCKOO_DEBUG_REHASH
#endif

/*----------------------------------------------------------------------------*/

#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed.\n")
#define ERR_WRONG_TABLE fprintf(stderr, "Wrong hash table used.\n")
#define ERR_INF_LOOP fprintf(stderr, "Hashing entered infinite loop.\n")
#define ERR_BITSET fprintf(stderr, "Bitset not correct.\n");
#define ERR_REHASHING_NOT_IMPL \
			fprintf(stderr, "Rehashing needed, but not supported.\n");

#define CK_SIZE CK_SIZE_LARGER

#define USED_SIZE 200

#define TABLE_1 0
#define TABLE_2 1
#define TABLE_FIRST TABLE_1
#define TABLE_LAST TABLE_2

#define NEXT_TABLE(table) ((table == TABLE_LAST) ? TABLE_FIRST : table + 1)
#define PREVIOUS_TABLE(table) ((table == TABLE_FIRST) ? TABLE_LAST : table - 1)

//#define HASH1(key, length, exp, gen) \
//            us_hash(jhash((unsigned char *)key, length, 0x0), exp, 0, gen)
#define HASH1(key, length, exp, gen) \
            us_hash(fnv_hash(key, length, -1), exp, 0, gen)
#define HASH2(key, length, exp, gen) \
            us_hash(fnv_hash(key, length, -1), exp, 1, gen)
//#define HASH2(key, length, exp, gen) \
//            us_hash(jhash((unsigned char *)key, length, 0x0), exp, 1, gen)

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
    return (flags ^ FLAG_GENERATION_BOTH);
}

/*----------------------------------------------------------------------------*/

#define CK_SIZE_NEAREST 1
#define CK_SIZE_LARGER 2

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
/**
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

static inline void ck_clear_item( ck_hash_table_item *item )
{
    memset(item, 0, sizeof(ck_hash_table_item));
}

/*----------------------------------------------------------------------------*/
/**
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
/**
 * @brief Insert contents of the first item to the second item.
 */
void ck_copy_item_contents(
	ck_hash_table_item *from, ck_hash_table_item *to)
{
	memcpy(to, from, sizeof(ck_hash_table_item));
}

/*----------------------------------------------------------------------------*/
/**
 * @brief Swaps two hash table items' contents.
 */
void ck_swap_items( ck_hash_table_item *item1, ck_hash_table_item *item2 )
{
	ck_hash_table_item tmp;

	ck_copy_item_contents(item1, &tmp);
	ck_copy_item_contents(item2, item1);
	ck_copy_item_contents(&tmp, item2);
}

/*----------------------------------------------------------------------------*/
/**
 * @brief Checks if the item in hash table was already used when rehashing item.
 */
int ck_check_used(bitset_t usedb, uint32_t hash )
{
	if (BITSET_ISSET(usedb, hash)) {
		ERR_INF_LOOP;
		return -1;
	} else {
		BITSET_SET(usedb, hash);
		return 0;
	}
}

/*----------------------------------------------------------------------------*/

uint ck_check_used2( uint *used, uint *last, uint32_t hash )
{
	uint i = 0;
	while (i <= *last && used[i] != hash) {
		++i;
	}

	if (i <= *last && used[i] == hash) {
		ERR_INF_LOOP;
		return -1;
	}
	else {
		assert(*last < USED_SIZE);
		*last = i;
		used[i] = hash;
		return 0;
	}
}

/*----------------------------------------------------------------------------*/

int ck_insert_to_buffer( ck_hash_table *table, ck_hash_table_item *item )
{
    assert(table->buf_i + 1 < BUFFER_SIZE);

	ck_copy_item_contents(item, &table->buffer[table->buf_i]);

	++table->buf_i;

    // if only one place left, rehash (this place is used in rehashing)
    if (table->buf_i + 1 == BUFFER_SIZE) {
        return ck_rehash(table);
    }

	return 0;
}

/*----------------------------------------------------------------------------*/

static inline uint ck_items_match( const ck_hash_table_item* item,
                                   const char *key, size_t length,
                                   uint generation )
{
    return (length == item->key_length
            && (strncmp(item->key, key, length) == 0)
            /*&& (GET_GENERATION(item->timestamp) == generation)*/) ? 0 : -1;
}

/*----------------------------------------------------------------------------*/

ck_hash_table_item *ck_find_in_buffer( ck_hash_table *table, const char *key,
                                       uint length, uint generation )
{
#ifdef CUCKOO_DEBUG
	printf("Max buffer offset: %u\n", table->buf_i);
#endif
	uint i = 0;
	while (i < table->buf_i
           && ck_items_match(&table->buffer[i], key, length, generation))
	{
		++i;
	}

	if (i >= table->buf_i) {
		return NULL;
	}

    assert(strncmp(table->buffer[i].key, key, length) == 0);
    //assert(GET_GENERATION(table->buffer[i].timestamp) == generation);

	return &table->buffer[i];
}

/*----------------------------------------------------------------------------*/

ck_hash_table *ck_create_table( uint items, void (*dtor_item)( void *value ) )
{
	ck_hash_table *table = (ck_hash_table *)malloc(sizeof(ck_hash_table));

	if (table == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	table->table_size_exp = get_table_exp(items, CK_SIZE);
    table->dtor_item = dtor_item;

//#ifdef CUCKOO_DEBUG
	printf("Creating hash table for %u items.\n", items);
	printf("Exponent: %u ", table->table_size_exp);
    printf("Table size: %u items, each %lu bytes, total %lu bytes\n",
		   hashsize(table->table_size_exp), sizeof(ck_hash_table_item),
		   hashsize(table->table_size_exp) * sizeof(ck_hash_table_item));
//#endif

    // Table 1
    table->table1 = (ck_hash_table_item *)malloc(hashsize(table->table_size_exp)
                                                 * sizeof(ck_hash_table_item));

	if (table->table1 == NULL) {
		ERR_ALLOC_FAILED;
		free(table);
		return NULL;
	}

	// set to 0
	memset(table->table1, 0,
		   hashsize(table->table_size_exp) * sizeof(ck_hash_table_item));

    // Table 2
    table->table2 = (ck_hash_table_item *)malloc(hashsize(table->table_size_exp)
                                                 * sizeof(ck_hash_table_item));

	if (table->table2 == NULL) {
		ERR_ALLOC_FAILED;
		free(table->table1);
		free(table);
		return NULL;
	}

	// set to 0
	memset(table->table2, 0,
		   hashsize(table->table_size_exp) * sizeof(ck_hash_table_item));

    // Buffer
	table->buffer = (ck_hash_table_item *)malloc(
						BUFFER_SIZE	* sizeof(ck_hash_table_item));

	if (table->buffer == NULL) {
		ERR_ALLOC_FAILED;
        free(table->table1);
		free(table->table2);
		free(table);
		return NULL;
	}

	// set to 0
	memset(table->buffer, 0, BUFFER_SIZE * sizeof(ck_hash_table_item));
	table->buf_i = 0;

    // initialize rehash mutex
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

#ifdef CUCKOO_DEBUG
    void  **used_pointers = malloc(hashsize((*table)->table_size_exp)
                                         * 2 * sizeof(void *));
    uint u = 0;
#endif

    // destroy items
    for (uint i = 0; i < hashsize((*table)->table_size_exp); ++i) {
        if ((*table)->table1[i].value != NULL) {
#ifdef CUCKOO_DEBUG
            printf("Deleting item from table 1 on pointer: %p.\n",
                   (*table)->table1[i].value);
            for (uint j = 0; j < u; ++j) {
                assert(used_pointers[j] != (*table)->table1[i].value);
            }
            used_pointers[u++] = (*table)->table1[i].value;
#endif

            (*table)->dtor_item((*table)->table1[i].value);
            (*table)->table1[i].value = NULL;

            free((void *)(*table)->table1[i].key);
        }
        if ((*table)->table2[i].value != NULL) {
#ifdef CUCKOO_DEBUG
            printf("Deleting item from table 2 on pointer: %p.\n",
                   (*table)->table2[i].value);
            for (uint j = 0; j < u; ++j) {
                assert(used_pointers[j] != (*table)->table2[i].value);
            }
            used_pointers[u++] = (*table)->table2[i].value;
#endif

            (*table)->dtor_item((*table)->table2[i].value);
            (*table)->table2[i].value = NULL;

            free((void *)(*table)->table2[i].key);
        }
    }

    for (uint i = 0; i < (*table)->buf_i; ++i) {
        assert((*table)->buffer[i].value != NULL);
#ifdef CUCKOO_DEBUG
        printf("Deleting item from buffer on pointer: %p.\n",
               (*table)->buffer[i].value);
        for (uint j = 0; j < u; ++j) {
            assert(used_pointers[j] != (*table)->buffer[i].value);
        }
        used_pointers[u++] = (*table)->buffer[i].value;
#endif
        (*table)->dtor_item((*table)->buffer[i].value);
        (*table)->buffer[i].value = NULL;
    }

#ifdef CUCKOO_DEBUG
    printf("Deleting: table1: %p, table2: %p, buffer: %p, table: %p.\n",
           (*table)->table1, (*table)->table2, (*table)->buffer, *table);
#endif

    pthread_mutex_unlock(&(*table)->mtx_table);
    // destroy mutex, assuming that here noone will lock the mutex again
    pthread_mutex_destroy(&(*table)->mtx_table);

    free((*table)->table1);
    (*table)->table1 = NULL;
    free((*table)->table2);
    (*table)->table2 = NULL;
    free((*table)->buffer);
    (*table)->buffer = NULL;
    free(*table);
    (*table) = NULL;
    // unlock
}

/*----------------------------------------------------------------------------*/

int ck_insert_item( ck_hash_table *table, const char *key,
					size_t length, void *value, unsigned long *collisions )
{
    pthread_mutex_lock(&table->mtx_table);
    
    uint32_t hash;
    ck_hash_table_item *moving, *next, old;
	int next_table;
    uint32_t used1[USED_SIZE], used2[USED_SIZE], used_i = 0;

#ifdef CUCKOO_DEBUG
	printf("Inserting item with key: %s.\n", key);
    hex_print(key, length);
#endif
    hash = HASH1(key, length, table->table_size_exp,
                 GET_GENERATION(table->generation));

	// try insert to first table
	if (table->table1[hash].value == 0) { // item free
        ck_fill_item(key, length, value, GET_GENERATION(table->generation),
                     &table->table1[hash]);
#ifdef CUCKOO_DEBUG
		printf("Inserted successfuly to table1, hash %u, key: %s.\n", hash,
			   table->table1[hash].key);
#endif
        pthread_mutex_unlock(&table->mtx_table);
		return 0;
    }

    // If failed, try to rehash the existing items until free place is found
#ifdef CUCKOO_DEBUG
	printf("Collision! Hash: %u\n", hash);
#endif

	(*collisions)++;

	memset(used1, 0, USED_SIZE);
	memset(used2, 0, USED_SIZE);

    ck_fill_item(key, length, value, GET_GENERATION(table->generation), &old);
	moving = &table->table1[hash];
	// remember that we used this cell
	used1[used_i] = hash;

#ifdef CUCKOO_DEBUG
	printf("Moving item from table1, key: %s, hash %u", moving->key, hash);
#endif
    hash = HASH2(moving->key, moving->key_length, table->table_size_exp,
                 GET_GENERATION(table->generation));

	used2[used_i] = hash;

	next = &table->table2[hash];
	next_table = TABLE_2;
#ifdef CUCKOO_DEBUG
	printf(" to table2, key: %s, hash %u\n", next->key, hash);
#endif
	while (next->value != 0) {
		// swap contents of the old item and the moving
		// thus remembering the moving item's contents
		ck_swap_items(&old, moving);

		moving = next;
#ifdef CUCKOO_DEBUG
		printf("Moving item from table %u, key: %s, hash %u",
			   next_table + 1, moving->key, hash);
#endif
		// rehash the next item to the proper table
		switch (next_table) {
			case TABLE_2:
                hash = HASH1(next->key, next->key_length, table->table_size_exp,
                             GET_GENERATION(table->generation));

				next = &table->table1[hash];
#ifdef CUCKOO_DEBUG
				printf(" to table 1, key: %s, hash %u\n", next->key, hash);
#endif
                if (ck_check_used2(used1, &used_i, hash) != 0) {
                    if (ck_insert_to_buffer(table, moving) == 0) {
						// put the old item to the new position
						ck_copy_item_contents(&old, moving);
                        pthread_mutex_unlock(&table->mtx_table);
						return 0;
					} else {
                        assert(0);
                        pthread_mutex_unlock(&table->mtx_table);
						return -1;
					}
				}
                next_table = NEXT_TABLE(next_table);
				break;
			case TABLE_1:
                hash = HASH2(next->key, next->key_length, table->table_size_exp,
                             GET_GENERATION(table->generation));

				next = &table->table2[hash];
#ifdef CUCKOO_DEBUG
				printf(" to table 2, key: %s, hash %u\n", next->key, hash);
#endif
                if (ck_check_used2(used2, &used_i, hash) != 0) {
                    if (ck_insert_to_buffer(table, moving) == 0) {
						// put the old item to the new position
						ck_copy_item_contents(&old, moving);
                        pthread_mutex_unlock(&table->mtx_table);
						return 0;
					} else {
                        assert(0);
                        pthread_mutex_unlock(&table->mtx_table);
						return -2;
					}
				}
                next_table = NEXT_TABLE(next_table);
				break;
			default:
				ERR_WRONG_TABLE;
                pthread_mutex_unlock(&table->mtx_table);
				return -3;
		}
	}

	assert(next->value == 0);

    ck_copy_item_contents(moving, next);
    ck_copy_item_contents(&old, moving);
#ifdef CUCKOO_DEBUG
    printf("Inserted successfuly, hash: %u.\n", hash);
#endif

    pthread_mutex_unlock(&table->mtx_table);
	return 0;
}

/*----------------------------------------------------------------------------*/

/**
 * @retval 0 if successful and no loop occured.
 * @retval 1 if a loop occured and the item was inserted to the @a free place.
 */
int ck_hash_item( ck_hash_table *table, ck_hash_table_item *old,
                  ck_hash_table_item *free )
{
    uint32_t hash;
    int next_table;
    uint8_t next_generation = NEXT_GENERATION(table->generation);

    uint32_t used1[USED_SIZE], used2[USED_SIZE];
    uint used_i1 = 0, used_i2 = 0;

    // hash until empty cell is encountered or until loop appears

    hash = HASH1(old->key, old->key_length, table->table_size_exp,
                 next_generation);

#ifdef CUCKOO_DEBUG_REHASH
    printf("New hash: %u.\n", hash);
#endif

    used1[used_i1] = hash;
    ck_hash_table_item *next = &table->table1[hash];
    ck_hash_table_item *moving = old;
    next_table = TABLE_2;

    while (next->value != NULL) {
        ck_swap_items(old, moving); // first time it's unnecessary
        // set the generation of the inserted item to the next generation
        SET_GENERATION(&moving->timestamp, next_generation);

        moving = next;

#ifdef CUCKOO_DEBUG_REHASH
        printf("Moving item from table %u, key: %s, hash %u",
               PREVIOUS_TABLE(next_table) + 1, moving->key, hash);
#endif

        // if the 'next' item is from the old generation, start from table 1
        if (GET_GENERATION(next->timestamp)
            == GET_GENERATION(table->generation)) {
            next_table = TABLE_1;
        }

        if (next_table == TABLE_1) {
            hash = HASH1(next->key, next->key_length, table->table_size_exp,
                         next_generation);
            next = &table->table1[hash];
#ifdef CUCKOO_DEBUG_REHASH
            printf(" to table 1, key: %s, hash %u\n", next->key, hash);
            printf("Generation of item: %hu, generation of table: %hu, "
                   "next generation: %u.\n",
                   GET_GENERATION(next->timestamp),
                   GET_GENERATION(table->generation),
                   next_generation);
#endif
            // check if this cell wasn't already used in this item's hashing
            if (ck_check_used2(used1, &used_i1, hash) != 0) {
                next = free;
                break;
            }
        } else if (next_table == TABLE_2) {
            hash = HASH2(next->key, next->key_length, table->table_size_exp,
                         next_generation);
            next = &table->table2[hash];
#ifdef CUCKOO_DEBUG_REHASH
            printf(" to table 2, key: %s, hash %u\n", next->key, hash);
#endif
            // check if this cell wasn't already used in this item's hashing
            if (ck_check_used2(used2, &used_i2, hash) != 0) {
                next = free;
                break;
            }

        } else {
            assert(0);
        }

        next_table = NEXT_TABLE(next_table);
    }

    assert(next->value == 0);

    ck_copy_item_contents(moving, next);
    // set the new generation for the inserted item
    SET_GENERATION(&next->timestamp, next_generation);
    ck_copy_item_contents(old, moving);
    // set the new generation for the inserted item
    SET_GENERATION(&moving->timestamp, next_generation);

    return (next == free) ? -1 : 0;
}

/*----------------------------------------------------------------------------*/

static inline void ck_set_generation_to_items( ck_hash_table_item *items,
                        uint32_t *indexes, uint index_count, uint8_t generation )
{
    for (uint i = 0; i < index_count; ++i) {
        // TODO: lcok the item!!
        SET_GENERATION(&items[indexes[i]].timestamp, generation);
    }
}

/*----------------------------------------------------------------------------*/

void ck_rollback_rehash( ck_hash_table *table )
{
    for (int i = 0; i < hashsize(table->table_size_exp); ++i) {
        // TODO: lock the item!!
        SET_GENERATION(&table->table1[i].timestamp, table->generation);
        // TODO: lock the item!!
        SET_GENERATION(&table->table2[i].timestamp, table->generation);
    }
}

/*----------------------------------------------------------------------------*/

int ck_rehash( ck_hash_table *table )
{
//    fprintf(stderr, "Rehashing not implemented yet!");
//    return -1;

    pthread_mutex_lock(&table->mtx_table);

    // we already have functions for the next generation, begin rehashing
    // we wil use the last item in the buffer as the old cell
    assert(table->buf_i + 1 <= BUFFER_SIZE);
    ck_hash_table_item *old = &table->buffer[table->buf_i];

    // rehash items from the first table
#ifdef CUCKOO_DEBUG_REHASH
    printf("Rehashing items from table 1.\n");
#endif
    uint rehashed = 0;
    while (rehashed < hashsize(table->table_size_exp)) {
#ifdef CUCKOO_DEBUG_REHASH
        printf("Rehashing item with hash %u, key (length %u): %*s, "
               "generation: %hu, table generation: %hu.\n", rehashed,
               table->table1[rehashed].key_length,
               table->table1[rehashed].key_length, table->table1[rehashed].key,
               GET_GENERATION(table->table1[rehashed].timestamp),
               GET_GENERATION(table->generation));
#endif

        // if item's generation is the new generation, skip
        if (table->table1[rehashed].value == NULL
            || (GET_GENERATION(table->table1[rehashed].timestamp)
                != GET_GENERATION(table->generation))) {

#ifdef CUCKOO_DEBUG_REHASH
            printf("Skipping item.\n");
#endif
            ++rehashed;
            continue;
        }
        // otherwise copy the item for rehashing

        ck_copy_item_contents(&table->table1[rehashed], old);
        // clear the place so that this item will not get rehashed again
        ck_clear_item(&table->table1[rehashed]);

        // and start rehashing
        if (ck_hash_item(table, old, &table->table1[rehashed])
            == -1) {
            ERR_INF_LOOP;
            // loop occured
            // TODO: must set old generation to all cells used for this rehash
            ck_rollback_rehash(table);

            pthread_mutex_unlock(&table->mtx_table);
            return -1;
        }

        ++rehashed;
    }

    // rehash items from the second table
#ifdef CUCKOO_DEBUG_REHASH
    printf("Rehashing items from table 2.\n");
#endif
    rehashed = 0;
    while (rehashed < hashsize(table->table_size_exp)) {
#ifdef CUCKOO_DEBUG_REHASH
        printf("Rehashing item with hash %u, key (length %u): %*s.\n", rehashed,
               table->table2[rehashed].key_length,
               table->table2[rehashed].key_length, table->table2[rehashed].key);
#endif
        // if item's generation is the new generation, skip
        if (GET_GENERATION(table->table2[rehashed].timestamp)
            != GET_GENERATION(table->generation)) {

#ifdef CUCKOO_DEBUG_REHASH
            printf("Skipping item.\n");
#endif
            ++rehashed;
            continue;
        }
        // otherwise copy the item for rehashing

        ck_copy_item_contents(&table->table2[rehashed], old);
        // clear the place so that this item will not get rehashed again
        ck_clear_item(&table->table2[rehashed]);

        // and start rehashing
        if (ck_hash_item(table, old, &table->table2[rehashed])
            == -1) {
            ERR_INF_LOOP;
            // loop occured
            // TODO: must set old generation to all cells used for this rehash
            ck_rollback_rehash(table);

            pthread_mutex_unlock(&table->mtx_table);
            return -1;
        }

        ++rehashed;
    }

    // rehashing completed, switch generation of the table
    SET_NEXT_GENERATION(&table->generation);

    pthread_mutex_unlock(&table->mtx_table);
    return 0;
}

/*----------------------------------------------------------------------------*/

const ck_hash_table_item *ck_find_item( ck_hash_table *table,
                                        const char *key, size_t length )
{
    uint32_t hash;

	// check first table
    hash = HASH1(key, length, table->table_size_exp,
                 GET_GENERATION(table->generation));

#ifdef CUCKOO_DEBUG
	printf("Hash: %u, key: %s\n", hash, key);
    printf("Table 1, hash: %u, key: %s, value: %s, key length: %lu\n",
           hash, table->table1[hash].key, (char *)table->table1[hash].value,
           table->table1[hash].key_length);
#endif

    if (ck_items_match(&table->table1[hash], key, length, table->generation)
        == 0) {
		// found
		return &table->table1[hash];
	}

	// check second table
    hash = HASH2(key, length, table->table_size_exp,
                 GET_GENERATION(table->generation));

#ifdef CUCKOO_DEBUG
    printf("Table 2, hash: %u, key: %s, value: %p, key length: %lu\n",
           hash, table->table2[hash].key, (char *)table->table2[hash].value,
           table->table2[hash].key_length);
#endif

    if (ck_items_match(&table->table2[hash], key, length, table->generation)
        == 0) {
		// found
		return &table->table2[hash];
	}

#ifdef CUCKOO_DEBUG
	printf("Searching in buffer...\n");
#endif

	// try to find in buffer
    ck_hash_table_item *found =
            ck_find_in_buffer(table, key, length,
                              GET_GENERATION(table->generation));

#ifdef CUCKOO_DEBUG
	printf("Found pointer: %p\n", found);
	if (found != NULL) {
        printf("Buffer, key: %s, value: %s, key length: %lu\n",
		   found->key, (char *)found->value, found->key_length);
	}
#endif

	// ck_find_in_buffer returns NULL if not found, otherwise pointer to item
	return found;
}

/*----------------------------------------------------------------------------*/

void ck_dump_table( ck_hash_table *table )
{
	uint i;

	// Assuming the keys and data are null-terminated strings

	printf("----------------------------------------------\n");
	printf("Hash table dump:\n\n");
	printf("Size of each table: %u\n\n", hashsize(table->table_size_exp));

	printf("Table 1:\n");

	for (i = 0; i < hashsize(table->table_size_exp); i++) {
		printf("Key: %u: %s ", i, table->table1[i].key);
		if (table->table1[i].value != 0) {
			printf("Value: %s.\n", (char *)table->table1[i].value);
		} else {
			printf("Empty\n");
		}
	}

	printf("\n\nTable 2:\n");

	for (i = 0; i < hashsize(table->table_size_exp); i++) {
		printf("Key: %u: %s ", i, table->table2[i].key);
		if (table->table2[i].value != 0) {
			printf("Value: %s.\n", (char *)table->table2[i].value);
		} else {
			printf("Empty\n");
		}
	}

	printf("\n");
}
