/**
 * @todo Dynamic array for keeping used indices when inserting.
 * @todo Implement d-ary cuckoo hashing / cuckoo hashing with buckets, or both.
 * @todo Implement rehashing.
 * @todo Remove the 'collisions' parameter from ck_insert_item().
 * @todo Use only one type of function (fnv or jenkins or some other) and
 *       different coeficients.
 * @todo Optimize the table for space (d-ary hashing will help).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     /* defines uint32_t etc */
#include <assert.h>

#include "cuckoo-hash-table.h"
#include "hash-functions.h"
#include "bitset.h"
#include "universal-system.h"

//#define DEBUG

/*----------------------------------------------------------------------------*/

#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed.\n")
#define ERR_WRONG_TABLE fprintf(stderr, "Wrong hash table used.\n")
#define ERR_INF_LOOP fprintf(stderr, "Hashing entered infinite loop,\n")
#define ERR_BITSET fprintf(stderr, "Bitset not correct.\n");
#define ERR_REHASHING_NOT_IMPL \
			fprintf(stderr, "Rehashing needed, but not supported.\n");

#define CK_SIZE CK_SIZE_LARGER

#define USED_SIZE 200

#define TABLE_1 0
#define TABLE_2 1
#define TABLE_FIRST TABLE_1
#define TABLE_LAST TABLE_2

#define NEXT_TABLE(table) table = (table == TABLE_LAST) ? TABLE_FIRST : table + 1

#define HASH1(key, length, exp) \
			us_hash(jhash((unsigned char *)key, length, 0x0), exp, 0, 1)
#define HASH2(key, length, exp) \
			us_hash(fnv_hash(key, length, -1), exp, 1, 2)

/*----------------------------------------------------------------------------*/

#define GENERATION_FLAG_BOTH		0x3	// 00000011

#define GET_GENERATION(flags)		(flags & GENERATION_FLAG_BOTH)
#define IS_GENERATION_1(flags)		((flags & GENERATION_FLAG_1) != 0)
#define SET_GENERATION_1(flags)		(flags = (flags & ~GENERATION_FLAG_2) \
										| GENERATION_FLAG_1)
#define IS_GENERATION_2(flags)		((flags & GENERATION_FLAG_2) != 0)
#define SET_GENERATION_2(flags)		(flags = (flags & ~GENERATION_FLAG_1) \
										| GENERATION_FLAG_2)
#define NEXT_GENERATION(flags)		(flags ^= GENERATION_FLAG_BOTH)

#define REHASH_IN_PROGRESS(flags)	((flags & REHASH_FLAG) != 0)
#define SET_REHASH(flags)			(flags |= REHASH_FLAG)
#define UNSET_REHASH(flags)			(flags &= ~REHASH_FLAG)

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
/**
 * @brief Insert given contents to the item.
 */
void ck_fill_item( const char *key, size_t key_length, void *value,
				   ck_hash_table_item *item )
{
	// must allocate new space for key and value, otherwise it will be lost!
	//item->key = malloc(key_length);
	//memcpy(item->key, key, key_length);
	item->key = key;
	item->key_length = key_length;
	item->value = value;
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
	if (table->buf_i == BUFFER_SIZE) {
		ERR_REHASHING_NOT_IMPL;
		return -1;
	}

	ck_copy_item_contents(item, &table->buffer[table->buf_i]);

	++table->buf_i;

	return 0;
}

/*----------------------------------------------------------------------------*/

ck_hash_table_item *ck_find_in_buffer( ck_hash_table *table, const char *key,
									   uint length )
{
#ifdef DEBUG
	printf("Max buffer offset: %u\n", table->buf_i);
#endif
	uint i = 0;
	while (i < table->buf_i
		   && (strncmp(table->buffer[i].key, key, length) != 0))
	{
		++i;
	}

	if (i >= table->buf_i) {
		return NULL;
	}

	return &table->buffer[i];
}

/*----------------------------------------------------------------------------*/

ck_hash_table *ck_create_table( uint items )
{
	ck_hash_table *table = (ck_hash_table *)malloc(sizeof(ck_hash_table));

	if (table == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	table->table_size_exp = get_table_exp(items, CK_SIZE);

//#ifdef DEBUG
	printf("Creating hash table for %u items.\n", items);
	printf("Exponent: %u ", table->table_size_exp);
    printf("Table size: %u items, each %lu bytes, total %lu bytes\n",
		   hashsize(table->table_size_exp), sizeof(ck_hash_table_item),
		   hashsize(table->table_size_exp) * sizeof(ck_hash_table_item));
//#endif

	/*
	 * Table 1
	 */
	table->table1 = (ck_hash_table_item *)malloc(
						hashsize(table->table_size_exp)
							* sizeof(ck_hash_table_item));

	if (table->table1 == NULL) {
		ERR_ALLOC_FAILED;
		free(table);
		return NULL;
	}

	// set to 0
	memset(table->table1, 0,
		   hashsize(table->table_size_exp) * sizeof(ck_hash_table_item));

	/*
	 * Table 2
	 */
	table->table2 = (ck_hash_table_item *)malloc(
						hashsize(table->table_size_exp)
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

	/*
	 * Buffer
	 */
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

	us_initialize();

	return table;
}

/*----------------------------------------------------------------------------*/

void ck_destroy_table( ck_hash_table *table )
{
	//BITSET_DESTROY(used1b);
	//BITSET_DESTROY(used2b);
	free(table->table1);
	free(table->table2);
	free(table);
}

/*----------------------------------------------------------------------------*/

int ck_insert_item( ck_hash_table *table, const char *key,
					size_t length, void *value, unsigned long *collisions )
{
	uint32_t hash/*, hash2*/;
	ck_hash_table_item/* *item,*/ *moving, *next, old;
	int next_table;
	uint used1[USED_SIZE], used2[USED_SIZE], used_i = 0;	// use dynamic array instead

#ifdef DEBUG
	printf("Inserting item with key: %s.\n", key);
#endif
	hash = HASH1(key, length, table->table_size_exp) /*& hashmask(table->table_size_exp)*/;

	// try insert to first table
	if (table->table1[hash].value == 0) { // item free
		ck_fill_item(key, length, value, &table->table1[hash]);
#ifdef DEBUG
		printf("Inserted successfuly to table1, hash %u, key: %s.\n", hash,
			   table->table1[hash].key);
#endif
		return 0;
	}

	/*
		If failed, try to rehash the existing items until free place is found
		rehashing is done by setting the initval to the initval of the table
		TODO: correct as appropriate
	*/
#ifdef DEBUG
	printf("Collision! Hash: %u\n", hash);
#endif

	(*collisions)++;

	//printf("Biset 1: %p, Bitset 2: %p\n", used1b, used2b);

	//BITSET_CREATE(used1b, hashsize(table->table_size_exp));
	//BITSET_CLEAR(used1b, hashsize(table->table_size_exp));
	//BITSET_CREATE(used2b, hashsize(table->table_size_exp));
	//BITSET_CLEAR(used2b, hashsize(table->table_size_exp));
	memset(used1, 0, USED_SIZE);
	memset(used2, 0, USED_SIZE);

	//printf("Bitset clear successful.\n");

	ck_fill_item(key, length, value, &old);
	moving = &table->table1[hash];
	// remember that we used this cell
	//BITSET_SET(used1b, hash);
	used1[used_i] = hash;

#ifdef DEBUG
	printf("Moving item from table1, key: %s, hash %u", moving->key, hash);
#endif
//	hash = HASH2(moving->key, moving->key_length) & hashmask(table->table_size_exp);
	hash = HASH2(moving->key, moving->key_length, table->table_size_exp);

	//BITSET_SET(used2b, hash);
	used2[used_i] = hash;

	next = &table->table2[hash];
	next_table = TABLE_2;
#ifdef DEBUG
	printf(" to table2, key: %s, hash %u\n", next->key, hash);
#endif
	while (next->value != 0) {
		// swap contents of the old item and the moving
		// thus remembering the moving item's contents
		ck_swap_items(&old, moving);

		moving = next;
#ifdef DEBUG
		printf("Moving item from table %u, key: %s, hash %u",
			   next_table + 1, moving->key, hash);
#endif
		// rehash the next item to the proper table
		switch (next_table) {
			case TABLE_2:
//				hash = HASH1(next->key, next->key_length)
//					   & hashmask(table->table_size_exp);
				hash = HASH1(next->key, next->key_length, table->table_size_exp);

				next = &table->table1[hash];
#ifdef DEBUG
				printf(" to table 1, key: %s, hash %u\n", next->key, hash);
#endif
				if (/*ck_check_used(used1b, hash)*/ck_check_used2(used1, &used_i, hash) != 0) {
					if (ck_insert_to_buffer(table, moving)) {
						// put the old item to the new position
						ck_copy_item_contents(&old, moving);
						return 0;
					} else {
						//BITSET_DESTROY(used1b);
						//BITSET_DESTROY(used2b);
						return -1;
					}
				}
				NEXT_TABLE(next_table);
				break;
			case TABLE_1:
//				hash = HASH2(next->key, next->key_length)
//						& hashmask(table->table_size_exp);
				hash = HASH2(next->key, next->key_length, table->table_size_exp);

				next = &table->table2[hash];
#ifdef DEBUG
				printf(" to table 2, key: %s, hash %u\n", next->key, hash);
#endif
				if (/*ck_check_used(used1b, hash)*/ck_check_used2(used2, &used_i, hash) != 0) {
					if (ck_insert_to_buffer(table, moving)) {
						// put the old item to the new position
						ck_copy_item_contents(&old, moving);
						return 0;
					} else {
						//BITSET_DESTROY(used1b);
						//BITSET_DESTROY(used2b);
						return -2;
					}
				}
				NEXT_TABLE(next_table);
				break;
			default:
				ERR_WRONG_TABLE;
				//BITSET_DESTROY(used1b);
				//BITSET_DESTROY(used2b);
				return -3;
		}
	}

	assert(next->value == 0);

	switch (next_table) {
		case TABLE_1:
			ck_copy_item_contents(moving, &table->table1[hash]);
			ck_copy_item_contents(&old, moving);
#ifdef DEBUG
			printf("Inserted successfuly, hash: %u.\n", hash);
#endif
			break;
		case TABLE_2:
			ck_copy_item_contents(moving, &table->table2[hash]);
			ck_copy_item_contents(&old, moving);
#ifdef DEBUG
			printf("Inserted successfuly, hash: %u.\n", hash);
#endif
			break;
		default:
			ERR_WRONG_TABLE;
			//BITSET_DESTROY(used1b);
			//BITSET_DESTROY(used2b);
			return -3;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int ck_rehash( ck_hash_table *table )
{
	fprintf(stderr, "Rehashing not implemented yet!");
	return -1;

	// no rehash if one is already in progress
	// TODO: synchronization or atomic swap needed
	if (REHASH_IN_PROGRESS(table->generation)) {
		return -1;
	} else {
		SET_REHASH(table->generation);
	}

	// we already have new functions for the next generation, so begin rehashing



	// TODO: synchronization!
	// get new function for the next generation
	if (us_next(NEXT_GENERATION(table->generation)) != 0) {
		return -2;		// rehashed, but no new functions
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

const ck_hash_table_item *ck_find_item( ck_hash_table *table, const char *key, size_t length )
{
	uint32_t hash/*, hash2*/;

	// check first table
//	hash = HASH1(key, length) & hashmask(table->table_size_exp);
	hash = HASH1(key, length, table->table_size_exp);

	//printf("Searching table 1, hash %u.\n", hash);

#ifdef DEBUG
	printf("Hash: %u, key: %s\n", hash, key);
	printf("Table 1, hash: %u, key: %s, value: %s, key length: %u\n",
		   hash, table->table1[hash].key, (char *)table->table1[hash].value, table->table1[hash].key_length);
#endif

	if (/*table->table1[hash].value != 0
		&& */length == table->table1[hash].key_length
		&& strncmp(table->table1[hash].key, key, length) == 0) {
		// found
		return &table->table1[hash];
	}

	// check second table
//	hash = HASH2(key, length) & hashmask(table->table_size_exp);
	hash = HASH2(key, length, table->table_size_exp);

#ifdef DEBUG
	printf("Table 2, hash: %u, key: %s, value: %s, key length: %u\n",
		   hash, table->table2[hash].key, (char *)table->table2[hash].value, table->table2[hash].key_length);
#endif

	//printf("Searching table 2, hash %u.\n", hash);

	if (/*table->table2[hash].value != 0
		&& */length == table->table2[hash].key_length
		&& strncmp(table->table2[hash].key, key, length) == 0) {
		// found
		return &table->table2[hash];
	}

#ifdef DEBUG
	printf("Searching in buffer...\n");
#endif

	// try to find in buffer
	ck_hash_table_item *found = ck_find_in_buffer(table, key, length);

#ifdef DEBUG
	printf("Found pointer: %p\n", found);
	if (found != NULL) {
		printf("Buffer, key: %s, value: %s, key length: %u\n",
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
