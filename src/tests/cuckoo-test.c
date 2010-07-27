#include "cuckoo-test.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <urcu.h>

#include "common.h"
#include "cuckoo-hash-table.h"
#include "dns-simple.h"
#include "socket-manager.h"
#include "dispatcher.h"
#include "dynamic-array.h"

//#define CK_TEST_DEBUG
//#define CK_TEST_LOOKUP
//#define CK_TEST_OUTPUT
//#define CK_TEST_REMOVE
//#define CK_TEST_COMPARE

#ifdef CK_TEST_DEBUG
	#define CK_TEST_LOOKUP
	#define CK_TEST_OUTPUT
	#define CK_TEST_REMOVE
	#define CK_TEST_COMPARE
#endif

#define ERR_COUNT 1
#define ERR_FILE_OPEN 2
#define ERR_FILE_READ 3
#define ERR_TABLE_CREATE 4
#define ERR_INSERT 5
#define ERR_LOOKUP 6
#define ERR_ALLOC_ITEMS 7
#define ERR_FIND 8
#define ERR_FILL 9
#define ERR_REMOVE 10

static const uint BUF_SIZE = 20;
static const uint ARRAY_SIZE = 500;

static const unsigned short PORT = 53535;
static const uint THREAD_COUNT = 2;

static const dnss_dname TEST_NAME1 = "seznam.cz.";
static const dnss_dname TEST_NAME2 = "google.cz.";
static uint DELETED_TEST_NAME;

/*----------------------------------------------------------------------------*/
// macro for hash table types

//#define CK_KEY_TYPE (char *)
//#define CK_VALUE_TYPE (char *)

/*----------------------------------------------------------------------------*/

// global var for counting collisions
//static unsigned long collisions = 0;

// static global var for the hash table (change later!)
static ck_hash_table *table;
static da_array items_not_found;
static da_array items_removed;

/*----------------------------------------------------------------------------*/

int ct_resize_buffer( char **buffer, uint *buf_size, int new_size, int item_size )
{
	char *new_buf;

	new_buf = realloc((void *)(*buffer), (new_size * item_size));
	// if error
	if (new_buf == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}
	*buffer = new_buf;
	*buf_size = new_size;

	return 0;
}

/*----------------------------------------------------------------------------*/

uint ct_get_line_count( FILE *file, unsigned long *chars )
{
	char ch = '\0';
	uint c = 0;

	*chars = 0;

	while (ch != EOF) {
		ch = fgetc(file);
		(*chars)++;
		if (ch == '\n') {
			//printf("Line: %u, chars: %u\n", c, *chars);
			c++;
		}
	}

	return c;
}

/*----------------------------------------------------------------------------*/

int ct_hash_from_file( FILE *file, ck_hash_table *table, uint items,
					unsigned long chars )
{
	uint buf_i, buf_size, res, key_size;
	char ch = '\0';
	char *buffer, *key;
	dnss_rr *value;
	int line = 0;
	unsigned long total_size = 0;

	while (ch != EOF) {
		buf_i = 0;
#ifdef CK_TEST_DEBUG
		printf("Allocating buffer\n");
#endif
		// allocate some buffer
		buf_size = BUF_SIZE;
		buffer = (char *)malloc(buf_size * sizeof(char));

		if (buffer == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}
#ifdef CK_TEST_DEBUG
		printf("Done\n");
#endif
		ch = fgetc(file);

		while (ch != ' ' && ch != '\n' && ch != EOF) {
//#ifdef CK_TEST_DEBUG
//            printf("Read character: %c\n", ch);
//#endif

			buffer[buf_i] = ch;
			buf_i++;

			// if the buffer is not big enough, re
			if ((buf_i >= buf_size)
				&& (ct_resize_buffer(&buffer, &buf_size,
								 buf_size * 2, sizeof(char)) != 0)) {
				// deallocate the last buffer used
				free(buffer);
				return -1;
			}

			ch = fgetc(file);
		}

		buffer[buf_i] = '\0';
		line++;

		// read rest of the characters (not interesting)
		while (ch != '\n' && ch != EOF) {
			ch = fgetc(file);
		}

#ifdef CK_TEST_DEBUG
		printf("Read domain name: %s\n", buffer);
#endif
		// if buffer too large
		if ((buf_size > buf_i + 1)
			&& (ct_resize_buffer(&buffer, &buf_size,
							 buf_i + 1, sizeof(char)) != 0)) {
			// deallocate the last buffer used
			free(buffer);
			return -1;
		}
#ifdef CK_TEST_DEBUG
		printf("Read domain name %s, inserting...\n", buffer);
#endif
		if (buf_i > 0) {
			// hash domain name

			total_size += (strlen(buffer) + 1);

			if (total_size > chars) {
				fprintf(stderr, "Error, more characters than expected! "
						"Expected %lu, found: %lu.\n", chars, total_size);
				free(buffer);
				return ERR_INSERT;
			}

#ifdef CK_TEST_DEBUG
			printf("Creating RR with the given owner name.\n");
#endif
			value = dnss_create_rr(buffer);
			if (value == NULL) {
				ERR_ALLOC_FAILED;
				free(buffer);
				return ERR_INSERT;
			}

			// try to delete the RR right away
//            dnss_destroy_rr(&value);
//            continue;

			// convert the domain name to wire format to be used for hashing
			key_size = dnss_wire_dname_size(&buffer);
			key = malloc(key_size);
			if (dnss_dname_to_wire(buffer, key, key_size) != 0) {
				dnss_destroy_rr(&value);
				free(buffer);
				free(key);
				return ERR_INSERT;
			}

#ifdef CK_TEST_DEBUG
			if (line % 100000 == 1) {
				fprintf(stderr, "Inserting item number %u, key: %s..\n",
						line, key);
				//hex_print(key, key_size);
			}
#endif

			if ((res = ck_insert_item(table, key, key_size - 1, value)) != 0) {
				fprintf(stderr, "\nInsert item returned %d.\n", res);
//                dnss_destroy_rr(&value);
//                free(key);
				free(buffer);
				return ERR_INSERT;
			}

#ifdef CK_TEST_DEBUG
			if (line % 100000 == 0) {
				fprintf(stderr, "Done.\n");
			}
#endif
		}
		free(buffer);	//unsigned long total_size = 0;
		buffer = NULL;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int ct_hash_names( ck_hash_table *table, char **domains, uint count )
{
	uint i = 0;
	int res;

	printf("Inserting items: \n");

	for (; i < count; i++) {
		//if ((i & (((uint32_t)1<<(10)) - 1)) == 0) printf("%u\n", i);
		if ((res =
				ck_insert_item(table, domains[i], strlen(domains[i]),
							   domains[i]))
			 != 0) {
			fprintf(stderr, "\nInsert item returned %d.\n", res);
			return ERR_INSERT;
		}
	}

	printf("\nDone.\n");

	return 0;
}

/*----------------------------------------------------------------------------*/

int ct_test_lookup( const ck_hash_table *table, const char *key, uint key_size )
{
	const ck_hash_table_item *item = NULL;

	if ((item = ck_find_item(table, key, key_size - 1)) == NULL
		|| strncmp(item->key, key, key_size - 1) != 0 ) {
#ifdef CK_TEST_LOOKUP
		fprintf(stderr, "\nItem with key %*s not found.\n", key_size, key);
#endif

		char *new_item = malloc(key_size * sizeof(char));
		strncpy(new_item, key, key_size);
		da_reserve(&items_not_found, 1);
		((char **)(da_get_items(&items_not_found)))[
				da_get_count(&items_not_found) - 1] = new_item;

		return 1;
	}

#ifdef CK_TEST_LOOKUP
	else {
		printf("Table 1, key: %s, rdata: %*s, key length: %lu\n",
			item->key, ((dnss_rr *)(item->value))->rdlength,
			((dnss_rr *)(item->value))->rdata, item->key_length);
	}
#endif
	return 0;
}

/*----------------------------------------------------------------------------*/

int ct_test_remove( const ck_hash_table *table, const char *key, uint key_size )
{
	if (rand() % 1000 == 1) {
		if (ck_remove_item(table, key, key_size - 1) != 0) {
			fprintf(stderr, "\nItem with key %*s not removed.\n",
					key_size, key);
			return ERR_REMOVE;
		} else {
#ifdef CK_TEST_REMOVE
			printf("Removed item with key: %*s\n", key_size, key);
#endif

			char *new_item = malloc(key_size * sizeof(char));
			strncpy(new_item, key, key_size);
			da_reserve(&items_removed, 1);
			((char **)(da_get_items(&items_removed)))[
					da_get_count(&items_removed) - 1] = new_item;
			return 1;
		}
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

int ct_test_fnc_from_file( ck_hash_table *table, FILE *file, int (*test_fnc)(
							const ck_hash_table *, const char *, uint) )
{
	uint buf_i, buf_size;
	char ch = '\0';
	char *buffer;

	fseek(file, 0, SEEK_SET);

	while (ch != EOF) {
		buf_i = 0;

#ifdef CK_TEST_DEBUG
		printf("Allocating buffer\n");
#endif

		// allocate some buffer
		buf_size = BUF_SIZE;
		buffer = (char *)malloc(buf_size * sizeof(char));

		if (buffer == NULL) {
			ERR_ALLOC_FAILED;
			return -1;
		}
#ifdef CK_TEST_DEBUG
		printf("Done\n");
#endif
		ch = fgetc(file);

		while ((ch != ' ' && ch != '\n') && ch != EOF) {
#ifdef CK_TEST_DEBUG
			printf("Read character: %c\n", ch);
#endif

			buffer[buf_i] = ch;
			buf_i++;

			// if the buffer is not big enough, re
			if ((buf_i >= buf_size)
				&& (ct_resize_buffer(&buffer, &buf_size,
								 buf_size * 2, sizeof(char)) != 0)) {
				// deallocate the last buffer used
				free(buffer);
				return -1;
			}

			ch = fgetc(file);
		}

		buffer[buf_i] = '\0';

		// read rest of the characters (not interesting)
		while (ch != '\n' && ch != EOF) {
			ch = fgetc(file);
		}

#ifdef CK_TEST_DEBUG
		printf("Read domain name: %s\n", buffer);
#endif

		// if buffer too large
		if ((buf_size > buf_i + 1)
			&& (ct_resize_buffer(&buffer, &buf_size,
							 buf_i + 1, sizeof(char)) != 0)) {
			// deallocate the last buffer used
			free(buffer);
			return -1;
		}

#ifdef CK_TEST_DEBUG
		printf("Read domain name %s, searching...\n", buffer);
#endif

		if (buf_i > 0) {
			// find domain name

			uint key_size = dnss_wire_dname_size(&buffer);
			char *key = malloc(key_size);
			if (dnss_dname_to_wire(buffer, key, key_size) != 0) {
				free(buffer);
				free(key);
				return -1;
			}

#ifdef CK_TEST_DEBUG
			printf("Wire format of the domain name:\n");
			hex_print(key, key_size);
#endif
			test_fnc(table, key, key_size);

			free(key);
		}
		free(buffer);
	}

	fprintf(stderr, "Items not found: %u.\n", da_get_count(&items_not_found));

	return (da_get_count(&items_not_found) == 0) ? 0 : -1;
}

/*----------------------------------------------------------------------------*/

void ct_destroy_items( void *item )
{
	dnss_rr *rr = (dnss_rr *)item;
	dnss_destroy_rr(&rr);
}

/*----------------------------------------------------------------------------*/

void ct_answer_request( const char *query_wire, uint size,
					 char *response_wire, uint *response_size )
	// in *response_size we have the maximum acceptable size of the response
{
#ifdef CK_TEST_OUTPUT
	printf("answer_request() called with query size %d.\n", size);
	hex_print(query_wire, size);
#endif

	dnss_packet *query = dnss_parse_query(query_wire, size);
	if (query == NULL) {
		return;
	}

#ifdef CK_TEST_OUTPUT
	printf("Query parsed, ID: %u, QNAME: %s\n", query->header.id,
		   query->questions[0].qname);
	hex_print(query->questions[0].qname, strlen(query->questions[0].qname));
#endif

	const ck_hash_table_item *item = ck_find_item(
			table, query->questions[0].qname,
			strlen(query->questions[0].qname));

	dnss_packet *response = dnss_create_empty_packet();
	if (response == NULL) {
		dnss_destroy_packet(&query);
		return;
	}

	if (item == NULL) {
#ifdef CK_TEST_OUTPUT
		printf("Requested name not found, returning empty response.\n");
#endif
		if (dnss_create_response(query, NULL, 0, &response) != 0) {
			dnss_destroy_packet(&query);
			dnss_destroy_packet(&response);
			return;
		}
	} else {
#ifdef CK_TEST_OUTPUT
		printf("Requested name found.\n");
#endif
		if (dnss_create_response(query, (dnss_rr *)item->value,
								 1, &response) != 0) {
			dnss_destroy_packet(&query);
			dnss_destroy_packet(&response);
			return;
		}
	}

#ifdef CK_TEST_OUTPUT
	printf("Response ID: %u\n", response->header.id);
#endif

	if (dnss_wire_format(response, response_wire, response_size) != 0) {
#ifdef CK_TEST_OUTPUT
		fprintf(stderr, "Response too long, returning SERVFAIL response.\n");
#endif
		if (dnss_create_error_response(query, &response) != 0) {
			dnss_destroy_packet(&query);
			dnss_destroy_packet(&response);
			return;
		}
		int res = dnss_wire_format(response, response_wire, response_size);
		assert(res != 0);
	}

#ifdef CK_TEST_OUTPUT
	printf("Returning response of size: %u.\n", *response_size);
#endif

	dnss_destroy_packet(&query);
	dnss_destroy_packet(&response);
}

/*----------------------------------------------------------------------------*/

int ct_count_domain_names( FILE *file, uint *names, unsigned long *chars )
{
	printf("Counting lines..");
	*names = ct_get_line_count(file, chars);
	printf("%u\n", *names);

	if (*names == -1) {
		fprintf(stderr, "Error reading domain names from file.\n");
		return ERR_FILE_READ;
	}

#ifdef CK_TEST_DEBUG
	printf("Domains read: %d.\n", *names);
#endif

	return 0;
}

/*----------------------------------------------------------------------------*/

int ct_fill_hash_table( ck_hash_table *table, FILE *file, uint names,
					 unsigned long chars )
{
	// hash the domain names
	int res = ct_hash_from_file(file, table, names, chars);

	if (res == 0) {
		printf("Successful.\n");
		printf("Number of items in the stash: %u\n", table->stash.count);
	} else {
		fprintf(stderr, "Error inserting names to the hash table.\n");
		return res;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int ct_create_and_fill_table( ck_hash_table **table, FILE *file )
{
	uint names;
	unsigned long chars;
	int res;

	if ((res = ct_count_domain_names(file, &names, &chars)) != 0) {
		fclose(file);
		return ERR_COUNT;
	}

	fseek(file, 0, SEEK_SET);

	*table = ck_create_table(names, ct_destroy_items);

	if (*table == NULL) {
		fprintf(stderr, "Error creating hash table.\n");
		return ERR_TABLE_CREATE;
	}

	if ((res = ct_fill_hash_table(*table, file, names, chars)) != 0) {
		return ERR_FILL;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

void ct_clear_items_array( da_array *items )
{
	uint count = da_get_count(items);

	for (uint i = 0; i < count; ++i) {
		free(((char **)(da_get_items(items)))[i]);
		da_release(items, 1);
	}
}

/*----------------------------------------------------------------------------*/

int ct_compare_items_array( da_array *items1, da_array *items2 )
{
	uint count1 = da_get_count(items1);
	uint count2 = da_get_count(items2);
	int errors = 0;
	DELETED_TEST_NAME = 0;

	uint dname_size = dnss_wire_dname_size(&TEST_NAME1);
	dnss_dname_wire test_dname = (dnss_dname_wire)malloc(dname_size);
	dnss_dname_to_wire(TEST_NAME1, test_dname, dname_size);

	for (uint i = 0; i < count1; ++i) {
		if (strncmp(((char **)(da_get_items(items1)))[i], test_dname,
					dname_size - 1) == 0) {
			DELETED_TEST_NAME = 1;
		}
		int found = 0;
		for (uint j = 0; j < count2; ++j) {
			if (strcmp(((char **)(da_get_items(items1)))[i],
					   ((char **)(da_get_items(items2)))[j]) == 0) {
				++found;
			}
		}
		if (found == 0) {
#ifdef CK_TEST_COMPARE
			fprintf(stderr, "Item with key %s found in first array, but not"
					" found in second one!\n",
					((char **)(da_get_items(items1)))[i]);
#endif
			++errors;
		}
		if (found > 1) {
#ifdef CK_TEST_COMPARE
			fprintf(stderr, "Item with key %s from first array, found in second"
					" array more than once!\n",
					((char **)(da_get_items(items1)))[i]);
#endif
			++errors;
		}
	}

	for (uint i = 0; i < count2; ++i) {
		int found = 0;
		for (uint j = 0; j < count1; ++j) {
			if (strcmp(((char **)(da_get_items(items1)))[j],
					   ((char **)(da_get_items(items2)))[i]) == 0) {
				++found;
			}
		}
		if (found == 0) {
#ifdef CK_TEST_COMPARE
			fprintf(stderr, "Item with key %s found in second array, but not"
					" found in first one!\n",
					((char **)(da_get_items(items2)))[i]);
#endif
			++errors;
		}
		if (found > 1) {
#ifdef CK_TEST_COMPARE
			fprintf(stderr, "Item with key %s from second array, found in first"
					" array more than once!\n",
					((char **)(da_get_items(items2)))[i]);
#endif
			++errors;
		}
	}

	fprintf(stderr, "Problems: %d\n", errors);

	return (errors == 0) ? 0 : -1;
}

/*----------------------------------------------------------------------------*/

void ct_waste_time( uint loops )
{
		int res;

		for (int j = 0; j <= loops; ++j) {
			res = 1;
			for (int i = 1; i <= 100; ++i) {
				res *= i;
			}
		}
		printf("Waste of time: %d\n", res);
}

/*----------------------------------------------------------------------------*/

void *ct_read_item( ck_hash_table *table, const dnss_dname test_name )
{
	// register thread to RCU
	rcu_register_thread();
	void *res = NULL;

	uint dname_size = dnss_wire_dname_size(&test_name);
	dnss_dname_wire test_dname = (dnss_dname_wire)malloc(dname_size);
	dnss_dname_to_wire(test_name, test_dname, dname_size);

	// get a reference to the item, protect by RCU
	printf("[Read] Acquiring reference to the item...\n");
	printf("[Read] Key: %*s, key size: %u\n", dname_size, test_dname,
		   dname_size);
	rcu_read_lock();
	const ck_hash_table_item *item = ck_find_item(table, test_dname,
												  dname_size - 1);
	if (item == NULL) {
		printf("[Read] Item not found in the table!\n");
		// unregister thread from RCU
		rcu_unregister_thread();
		return NULL;
	}
	printf("[Read] Found item with key: %*s, value: %p\n", item->key_length,
		   item->key, item->value);

	// wait some time, so that the item is deleted
	printf("[Read] Waiting...\n");
	ct_waste_time(5000000);
	printf("[Read] Done.\n");

	printf("[Read] Still holding item with key: %*s, value: %p\n",
		   item->key_length, item->key, item->value);

	// release the pointer
	printf("[Read] Releasing the item...\n");
	item = NULL;
	rcu_read_unlock();
	printf("[Read] Done.\n");

	// try to find the item again; should not be successful
	printf("[Read] Trying to find the item again...\n");
	if (ck_find_item(table, test_dname, dname_size - 1) == NULL) {
		printf("[Read] Item not found in the table.\n");
	} else {
		printf("[Read] Item still found in the table.\n");
		res = (void *)(1);
	}

	// unregister thread from RCU
	rcu_unregister_thread();

	return res;
}

/*----------------------------------------------------------------------------*/

static inline void *ct_read_item1( void *obj )
{
	return ct_read_item((ck_hash_table *)obj, TEST_NAME1);
}

/*----------------------------------------------------------------------------*/

static inline void *ct_read_item2( void *obj )
{
	return ct_read_item((ck_hash_table *)obj, TEST_NAME2);
}

/*----------------------------------------------------------------------------*/

int ct_delete_item_during_read( ck_hash_table *table )
{
	pthread_t thread;

	uint dname_size = dnss_wire_dname_size(&TEST_NAME1);
	dnss_dname_wire test_dname = (dnss_dname_wire)malloc(dname_size);
	dnss_dname_to_wire(TEST_NAME1, test_dname, dname_size);

	// create thread for reading
	printf("[Delete] Creating thread for reading...\n");
	if (pthread_create(&thread, NULL, ct_read_item1, (void *)table)) {
		log_error("%s: failed to create reading thread.", __func__);
		return -1;
	}
	printf("[Delete] Done.\n");

	// wait some time, so the other thread gets the item for reading
	printf("[Delete] Waiting...\n");
	ct_waste_time(1000);
	printf("[Delete] Done.\n");

	// delete the item from the table
	printf("[Delete] Removing the item from the table...\n");
	if (ck_remove_item(table, test_dname, dname_size - 1) != 0) {
		fprintf(stderr, "Item not removed from the table!\n");
		return -2;
	}
	printf("[Delete] Done.\n");

	// wait for the thread
	printf("[Delete] Waiting for the reader thread to finish...\n");
	void *ret = NULL;
	if (pthread_join(thread, &ret)) {
		log_error("%s: failed to join reading thread.", __func__);
		return -1;
	}
	printf("[Delete] Done.\n");

	return (int)ret;
}

/*----------------------------------------------------------------------------*/

int ct_rehash_during_read( ck_hash_table *table )
{
	pthread_t thread;

	uint dname_size = dnss_wire_dname_size(&TEST_NAME2);
	dnss_dname_wire test_dname = (dnss_dname_wire)malloc(dname_size);
	dnss_dname_to_wire(TEST_NAME2, test_dname, dname_size);

	// create thread for reading
	printf("[Delete] Creating thread for reading...\n");
	if (pthread_create(&thread, NULL, ct_read_item2, (void *)table)) {
		log_error("%s: failed to create reading thread.", __func__);
		return -1;
	}
	printf("[Delete] Done.\n");

	// wait some time, so the other thread gets the item for reading
	printf("[Delete] Waiting...\n");
	ct_waste_time(1000);
	printf("[Delete] Done.\n");

	// delete the item from the table
	printf("[Delete] Rehashing items in table...\n");
	if (ck_rehash(table) != 0) {
		fprintf(stderr, "Rehashing not successful!\n");
		return -2;
	}
	printf("[Delete] Done.\n");

	// wait for the thread
	printf("[Delete] Waiting for the reader thread to finish...\n");
	void *ret = NULL;
	if (pthread_join(thread, &ret)) {
		log_error("%s: failed to join reading thread.", __func__);
		return -1;
	}
	printf("[Delete] Done.\n");

	return (int)ret;
}

/*----------------------------------------------------------------------------*/

int ct_test_hash_table( char *filename )
{
	// initialize RCU
	rcu_init();

	// register thread to RCU
	rcu_register_thread();

	printf("Testing hash table...\n\n");

	srand(time(NULL));

	int res = 0;
	da_initialize(&items_not_found, 1000, sizeof(char *));
	da_initialize(&items_removed, 1000, sizeof(char *));

	for (int i = 0; i < 1; ++i) {

		printf("----------------------------\n");
		printf("-----Iteration %d------------\n", i);
		printf("----------------------------\n");

		printf("Opening file...");

		FILE *file = fopen(filename, "r");

		if (file == NULL) {
			fprintf(stderr, "Can't open file: %s.\n", filename);
			return ERR_FILE_OPEN;
		}

		printf("Done.\n");

		printf("Creating and filling the table...\n\n");
		res = ct_create_and_fill_table(&table, file);

		switch (res) {
			case ERR_FILL:
				ck_destroy_table(&table);
			case ERR_COUNT:
			case ERR_TABLE_CREATE:
				return res;
		}

		printf("\nDone. Result: %d\n\n", res);

		printf("Testing lookup...\n\n");
		res = ct_test_fnc_from_file(table, file, ct_test_lookup);
		printf("\nDone. Items not found: %d\n\n",
			   da_get_count(&items_not_found));
		ct_clear_items_array(&items_not_found);

		printf("Testing rehash...\n");
		int res_rehash = ck_rehash(table);
		printf("\nDone. Result: %d\n\n", res_rehash);

		printf("Testing another rehash...\n");
		res_rehash = ck_rehash(table);
		printf("\nDone. Result: %d\n\n", res_rehash);

		printf("Testing lookup...\n\n");
		res = ct_test_fnc_from_file(table, file, ct_test_lookup);
		printf("\nDone. Items not found: %d\n\n",
			   da_get_count(&items_not_found));
		ct_clear_items_array(&items_not_found);

		printf("Testing removal...\n\n");
		res = ct_test_fnc_from_file(table, file, ct_test_remove);
		printf("\nDone. Items removed: %d\n\n", da_get_count(&items_removed));

		printf("Testing lookup...\n\n");
		res = ct_test_fnc_from_file(table, file, ct_test_lookup);
		printf("\nDone. Result: %d\n\n", res);

		printf("Comparing array of not found items with array of removed "
			   "items...\n\n");
		res = ct_compare_items_array(&items_not_found, &items_removed);
		printf("\nDone. Result: %d\n\n", res);

		ct_clear_items_array(&items_removed);
		ct_clear_items_array(&items_not_found);

		printf("Testing delete during read...\n\n");
		if (DELETED_TEST_NAME != 0) {
			printf("Test name deleted, skipping delete test...\n");
		} else {
			res = ct_delete_item_during_read(table);
			printf("\nDone. Result: %d\n\n", res);
		}

		printf("Testing rehash during read...\n\n");
		res = ct_rehash_during_read(table);
		printf("\nDone. Result: %d\n\n", res);

		ck_destroy_table(&table);
		fclose(file);

		//if (res != 0) break;

	}

	da_destroy(&items_not_found);
	da_destroy(&items_removed);

	// unregister thread from RCU
	rcu_unregister_thread();

	return res;
}

/*----------------------------------------------------------------------------*/

int ct_start_server( char *filename )
{
	printf("Starting server...\n\n");

	printf("Opening file...");

	FILE *file = fopen(filename, "r");

	if (file == NULL) {
		fprintf(stderr, "Can't open file: %s.\n", filename);
		return ERR_FILE_OPEN;
	}

	printf("Done.\n\n");

	printf("Creating and filling the table...\n\n");
	uint res = ct_create_and_fill_table(&table, file);

	switch (res) {
		case ERR_FILL:
			ck_destroy_table(&table);
		case ERR_COUNT:
		case ERR_TABLE_CREATE:
			printf("Error %u.\n", res);
			return res;
	}

	printf("\nDone.\n\n");

	fclose(file);

	printf("Rest of the test not implemented.\n");
	return -1;

//    printf("Creating socket manager...\n\n");
//    sm_manager *manager = sm_create(PORT, answer_request);
//    if (manager == NULL) {
//        ck_destroy_table(&table);
//        return -1;
//    }
//    printf("\nDone.\n\n");
//
//    printf("Creating dispatcher...\n\n");
//    dpt_dispatcher *dispatcher = dpt_create(THREAD_COUNT, sm_listen, manager);
//    if (dispatcher == NULL) {
//        ck_destroy_table(&table);
//        sm_destroy(&manager);
//        return -1;
//    }
//    printf("\nDone.\n\n");
//
//    printf("Starting dispatcher...\n");
//    dpt_start(dispatcher);
//
//    // can I do this?? pointer to the manager is still in the threads
//    sm_destroy(&manager);
//
//    ck_destroy_table(&table);
//
//    return 0;
}
