#ifndef CUCKOO_HASH_TABLE
#define CUCKOO_HASH_TABLE

#include <stdint.h>	/* uint32_t */
#include <stdlib.h>	/* size_t */
#include "common.h"

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

#define BUFFER_SIZE 1000

#define GENERATION_FLAG_1			0x1	// 00000001
#define GENERATION_FLAG_2			0x2	// 00000010
#define REHASH_FLAG					0x4 // 00000100

/*----------------------------------------------------------------------------*/

struct ck_hash_table_item {
	const char *key;
	size_t key_length;
	void *value;
	uint8_t timestamp;	// 000000xy; xy .. generation; may be 01 or 10
};	// size 13 B

typedef struct ck_hash_table_item ck_hash_table_item;

/*----------------------------------------------------------------------------*/

struct ck_hash_table {
	int table_size_exp;		// exponent (2^table_size_exp is table size)
							// -1 if not initialized
	ck_hash_table_item *table1;
	ck_hash_table_item *table2;
	ck_hash_table_item *buffer;
	uint buf_i;
	uint8_t generation;		/* 00000xyz x==1 .. rehashing in progress
										yz   .. generation; may be 01 or 10 */
};

typedef struct ck_hash_table ck_hash_table;

/*----------------------------------------------------------------------------*/

ck_hash_table *ck_create_table( uint items );

/*----------------------------------------------------------------------------*/

void ck_destroy_table( ck_hash_table *table );

/*----------------------------------------------------------------------------*/
/**
 * @brief Inserts item into the hash table.
 *
 * @retval 0 No error.
 * @retval -1 Insertion failed.
 */
int ck_insert_item( ck_hash_table *table, const char *key,
					size_t length, void *value, unsigned long *collisions );

/*----------------------------------------------------------------------------*/

int ck_rehash( ck_hash_table *table );

/*----------------------------------------------------------------------------*/
/**
 * @brief Finds item in table.
 */
const ck_hash_table_item *ck_find_item(
		ck_hash_table *table, const char *key, size_t length );

/*----------------------------------------------------------------------------*/
/**
 * @brief Dumps the whole hash table.
 */
void ck_dump_table( ck_hash_table *table );

/*----------------------------------------------------------------------------*/

/**
 * @todo Check size of integers, the table size may be larger than unsigned int.
 * @todo Generalize to be k-ary cuckoo hashing (not dependent on number of
 *       tables.
 */
#endif
