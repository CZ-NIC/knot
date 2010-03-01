/**
 * @todo Do not hash the string with the ending '\0'.
 */

#include "cuckoo-hash-table.h"
#include <stdio.h>
#include <string.h>

#include "bitset.h"

#define ERR_ARG 1
#define ERR_FILE_OPEN 2
#define ERR_FILE_READ 3
#define ERR_TABLE_CREATE 4
#define ERR_INSERT 5
#define ERR_LOOKUP 6
#define ERR_ALLOC_ITEMS 7
#define ERR_FIND 8

#define BUF_SIZE 20
#define ARRAY_SIZE 500

/*----------------------------------------------------------------------------*/
// macro for hash table types

#define CK_KEY_TYPE (char *)
#define CK_VALUE_TYPE (char *)

/*----------------------------------------------------------------------------*/

// global var for counting collisions
unsigned long collisions = 0;

/*----------------------------------------------------------------------------*/

int resize_buffer( char **buffer, uint *buf_size, int new_size, int item_size )
{
	char *new_buf;

	new_buf = realloc((void *)(*buffer), (new_size * item_size));
	// if error
	if (new_buf == NULL) {
		fprintf(stderr, "Allocation failed.\n");
		return -1;
	}
	*buffer = new_buf;
	*buf_size = new_size;

	return 0;
}

/*----------------------------------------------------------------------------*/

void deallocate_array_items( char **arr, int size )
{
	while (--size >= 0) {
		free((void *)(arr[size]));
	}
}

/*----------------------------------------------------------------------------*/

void clean_table( char *place )
{
	free(place);
}

/*----------------------------------------------------------------------------*/

uint get_line_count( FILE *file, unsigned long *chars )
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

int hash_from_file( FILE *file, ck_hash_table *table, uint items,
					unsigned long chars, char *place )
{
	uint /*arr_i,*/ buf_i, buf_size/*, arr_size*/, res;
	char ch = '\0';
	char *buffer, *key, *value;
	int line = 0;
	unsigned long total_size = 0;

	//printf("Place pointer received: %p\n", place);

	key = place;
	value = place;

	while (ch != EOF) {
		buf_i = 0;

		//printf("Allocating buffer\n");

		// allocate some buffer
		buf_size = BUF_SIZE;
		buffer = (char *)malloc(buf_size * sizeof(char));

		if (buffer == NULL) {
			fprintf(stderr, "Allocation failed.\n");
			return -1;
		}

		//printf("Done\n");

		ch = fgetc(file);

		while (ch != '\n' && ch != EOF) {
			//printf("Read character: %c\n", ch);

			buffer[buf_i] = ch;
			buf_i++;

			// if the buffer is not big enough, re
			if ((buf_i >= buf_size)
				&& (resize_buffer(&buffer, &buf_size,
								 buf_size * 2, sizeof(char)) != 0)) {
				// deallocate the last buffer used
				free(buffer);
				return -1;
			}

			ch = fgetc(file);
		}

		//printf("End of first item\n");

		buffer[buf_i] = '\0';
		line++;
		//printf("Read domain name: %s\n", buffer);

		// if buffer too large
		if ((buf_size > buf_i + 1)
			&& (resize_buffer(&buffer, &buf_size,
							 buf_i + 1, sizeof(char)) != 0)) {
			// deallocate the last buffer used
			free(buffer);
			return -1;
		}

		//printf("Read domain name %s, inserting...\n", buffer);

		if (buf_i > 0) {
			// hash domain name

			total_size += (strlen(buffer) + 1);

			if (total_size > chars) {
				fprintf(stderr, "Error, more characters than expected! "
						"Expected %lu, found: %lu.\n", chars, total_size);
				free(buffer);
				return ERR_INSERT;
			}

			//printf("Copying buffer to place %p\n", key);
			memcpy(key, buffer, strlen(buffer) + 1);
			value += strlen(buffer) + 1;
			memcpy(value, buffer, strlen(buffer) + 1);

//			if (line % 100000 == 0) {
//				fprintf(stderr, "Inserting item number %u, key: %s..\n", line, key);
//			}

            if ((res = ck_insert_item(
                    table, key, strlen(buffer), value, &collisions)) != 0) {
				fprintf(stderr, "\nInsert item returned %d.\n", res);
				free(buffer);
				return ERR_INSERT;
			}

			key = value + strlen(buffer) + 1;
			value = key;

//			if (line % 100000 == 0) {
//				fprintf(stderr, "Done, %lu collisions so far.\n", collisions);
//			}
		}
		free(buffer);
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int hash_names( ck_hash_table *table, char **domains, uint count )
{
	uint i = 0;
	int res;

	printf("Inserting items: \n");

	for (; i < count; i++) {
		//if ((i & (((uint32_t)1<<(10)) - 1)) == 0) printf("%u\n", i);
		if ((res =
				ck_insert_item(table, domains[i], strlen(domains[i]),
							   domains[i], &collisions))
			 != 0) {
			fprintf(stderr, "\nInsert item returned %d.\n", res);
			return ERR_INSERT;
		}
	}

	printf("\nDone.\n");

	return 0;
}

/*----------------------------------------------------------------------------*/

int test_lookup_from_file( ck_hash_table *table, FILE *file )
{
	uint buf_i, buf_size, not_found = 0;
	char ch = '\0';
	char *buffer;
	ck_hash_table_item *res;
	//unsigned long total_size = 0;

	while (ch != EOF) {
		buf_i = 0;

		//printf("Allocating buffer\n");

		// allocate some buffer
		buf_size = BUF_SIZE;
		buffer = (char *)malloc(buf_size * sizeof(char));

		if (buffer == NULL) {
			fprintf(stderr, "Allocation failed.\n");
			return -1;
		}

		//printf("Done\n");

		ch = fgetc(file);

		while (ch != '\n' && ch != EOF) {
			//printf("Read character: %c\n", ch);

			buffer[buf_i] = ch;
			buf_i++;

			// if the buffer is not big enough, re
			if ((buf_i >= buf_size)
				&& (resize_buffer(&buffer, &buf_size,
								 buf_size * 2, sizeof(char)) != 0)) {
				// deallocate the last buffer used
				free(buffer);
				return -1;
			}

			ch = fgetc(file);
		}

		//printf("End of first item\n");

		buffer[buf_i] = '\0';
		//printf("Read domain name: %s\n", buffer);

		// if buffer too large
		if ((buf_size > buf_i + 1)
			&& (resize_buffer(&buffer, &buf_size,
							 buf_i + 1, sizeof(char)) != 0)) {
			// deallocate the last buffer used
			free(buffer);
			return -1;
		}

		//printf("Read domain name %s, inserting...\n", buffer);

		if (buf_i > 0) {
			// find domain name

			if ((res = ck_find_item(table, buffer, strlen(buffer))) == NULL
				|| strncmp(res->key, buffer, strlen(buffer)) != 0 ) {
				//fprintf(stderr, "\nItem with key %s not found.\n", buffer);
				not_found++;
//				free(buffer);
//				return ERR_FIND;
			}/* else {
				printf("Table 1, key: %s, value: %s, key length: %u\n",
					res->key, (char *)res->value, res->key_length);
			}*/
		}
		free(buffer);
	}

	fprintf(stderr, "Items not found: %u.\n", not_found);

	return not_found;
}

/*----------------------------------------------------------------------------*/

int test_bitset() {
	bitset_t bitset;
	uint n = 1048576, i, c, err = 0;
	uint *numbers = malloc(n/2 * sizeof(uint));

	BITSET_CREATE(&bitset, n);
	BITSET_CLEAR(bitset, n);

	printf("New bitset created.\n");

	// check if empty
	for (i = 0; i < n; i++) {
		if (BITSET_GET(bitset, i) != 0) {
			printf("Bit %u not clear!\n", i);
			err++;
		}
	}

	srand(1);

	printf("Setting random bits...\n");

	// set random bits, but keep track of them
	for (i = 0; i < n/2; i++) {
		c = rand() % n;
		//printf("Setting bit on position %u..\n", c);
		numbers[i] = c;
		BITSET_SET(bitset, c);

		if (!BITSET_ISSET(bitset, c)) {
			printf("Bit %u not set successfully!\n", c);
			err++;
		}

		BITSET_UNSET(bitset, c);
	}

	printf("Testing borders...\n");
	// setting bits on the borders
	BITSET_SET(bitset, 0);
	if (!BITSET_ISSET(bitset, 0)) {
		printf("Error setting bit on position 0.\n");
		err++;
	}
	BITSET_UNSET(bitset, 0);

	BITSET_SET(bitset, 31);
	if (!BITSET_ISSET(bitset, 31)) {
		printf("Error setting bit on position 31.\n");
		err++;
	}
	BITSET_UNSET(bitset, 31);

	BITSET_SET(bitset, 32);
	if (!BITSET_ISSET(bitset, 32)) {
		printf("Error setting bit on position 32.\n");
		err++;
	}
	BITSET_UNSET(bitset, 32);

	BITSET_SET(bitset, 33);
	if (!BITSET_ISSET(bitset, 33)) {
		printf("Error setting bit on position 33.\n");
		err++;
	}
	BITSET_UNSET(bitset, 33);

	BITSET_SET(bitset, 1048575);
	if (!BITSET_ISSET(bitset, 1048575)) {
		printf("Error setting bit on position 1048575.\n");
		err++;
	}
	BITSET_UNSET(bitset, 1048575);

	// check if empty
	for (i = 0; i < n; i++) {
		if (BITSET_GET(bitset, i) != 0) {
			printf("Bit %u not clear!\n", i);
			err++;
		}
	}

	free(numbers);
	BITSET_DESTROY(bitset);

	printf("There were %u errors.\n", err);
	return 0;
}

/*----------------------------------------------------------------------------*/

int main( int argc, char **argv )
{
	FILE *file;
	uint names;
	int res;
	unsigned long chars;
	char *all_items;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <filename>.\n", argv[0]);
		return ERR_ARG;
	}

	file = fopen(argv[1], "r");

	if (file == NULL) {
		fprintf(stderr, "Can't open file: %s.\n", argv[1]);
		return ERR_FILE_OPEN;
	}

	printf("Counting lines..");
	names = get_line_count(file, &chars);
	printf("%u\n", names);
	//fclose(file);

	if (names == -1) {
		fprintf(stderr, "Error reading domain names from file.\n");
		return ERR_FILE_READ;
	}

	//fprintf(stderr, "Domains read: %d.\n", names);

	ck_hash_table *table = ck_create_table(names);

	if (table == NULL) {
		fprintf(stderr, "Error creating hash table.\n");
		return ERR_TABLE_CREATE;
	}

	fseek(file, 0, SEEK_SET);

	if (chars * 2 * sizeof(char) > SIZE_MAX) {
		fprintf(stderr, "Size of input larger than max size for malloc."
                "Input size: %lu, malloc max size: %lu.\n",
				chars * 2 * sizeof(char), SIZE_MAX);
		return ERR_ALLOC_ITEMS;
	}

	printf("Creating place for all items, size: %lu.\n",
		   chars * 2 * sizeof(char));

	// allocate space for all items
	all_items = malloc(chars * 2 * sizeof(char));

	if (all_items == NULL) {
		fprintf(stderr, "Error allocating place for all items.\n");
		return ERR_ALLOC_ITEMS;
	}

	printf("Done: %p\n", all_items);

	// hash the domain names
	res = hash_from_file(file, table, names, chars, all_items);

	//fclose(file);

	if (res == 0) {
		//ck_dump_table(table);

		//test_lookup(table, domains, names);
		printf("Probably successful.\n");
		printf("Number of items in the buffer: %u\n", table->buf_i + 1);
	} else {
		//ck_dump_table(table);

		fprintf(stderr, "Error inserting names to the hash table.\n");
//		ck_destroy_table(table);
//		clean_table(all_items);
//		return res;
	}

	fseek(file, 0, SEEK_SET);

//	ck_dump_table(table);
//	exit(1);

	res = test_lookup_from_file(table, file);

	ck_destroy_table(table);

	clean_table(all_items);
	//deallocate_array_items(domains, names);

	return res;
}
