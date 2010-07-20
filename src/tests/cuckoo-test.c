#include "cuckoo-test.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "common.h"
#include "cuckoo-hash-table.h"
#include "dns-simple.h"
#include "socket-manager.h"
#include "dispatcher.h"

//#define CK_TEST_DEBUG
//#define CK_TEST_LOOKUP
//#define CK_TEST_OUTPUT

#ifdef CK_TEST_DEBUG
    #define CK_TEST_LOOKUP
    #define CK_TEST_OUTPUT
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

static const uint BUF_SIZE = 20;
static const uint ARRAY_SIZE = 500;

static const unsigned short PORT = 53535;
static const uint THREAD_COUNT = 2;

/*----------------------------------------------------------------------------*/
// macro for hash table types

//#define CK_KEY_TYPE (char *)
//#define CK_VALUE_TYPE (char *)

/*----------------------------------------------------------------------------*/

// global var for counting collisions
//static unsigned long collisions = 0;

// static global var for the hash table (change later!)
static ck_hash_table *table;

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
			fprintf(stderr, "Allocation failed.\n");
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
				&& (resize_buffer(&buffer, &buf_size,
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
			&& (resize_buffer(&buffer, &buf_size,
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
                fprintf(stderr, "Allocation failed in hash_from_file().");
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

            if ((res = ck_insert_item(table, key,
                                      key_size - 1,
                                      value)) != 0) {
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

int hash_names( ck_hash_table *table, char **domains, uint count )
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

int test_lookup_from_file( ck_hash_table *table, FILE *file )
{
	uint buf_i, buf_size, not_found = 0;
	char ch = '\0';
	char *buffer;
    const ck_hash_table_item *res;

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
			fprintf(stderr, "Allocation failed.\n");
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
				&& (resize_buffer(&buffer, &buf_size,
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
			&& (resize_buffer(&buffer, &buf_size,
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

            if ((res = ck_find_item(table, key,
                                    key_size - 1)) == NULL
                || strncmp(res->key, key, key_size - 1) != 0 ) {
                fprintf(stderr, "\nItem with key %s not found.\n", buffer);
                free(key);
                free(buffer);
                return ERR_FIND;
            }

#ifdef CK_TEST_LOOKUP
            else {
                printf("Table 1, key: %s, rdata: %*s, key length: %lu\n",
                    res->key, ((dnss_rr *)(res->value))->rdlength,
                    ((dnss_rr *)(res->value))->rdata, res->key_length);
            }
#endif
            free(key);
		}
		free(buffer);
	}

	fprintf(stderr, "Items not found: %u.\n", not_found);

	return not_found;
}

/*----------------------------------------------------------------------------*/

void destroy_items( void *item )
{
    dnss_rr *rr = (dnss_rr *)item;
    dnss_destroy_rr(&rr);
}

/*----------------------------------------------------------------------------*/

void answer_request( const char *query_wire, uint size,
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

int count_domain_names( FILE *file, uint *names, unsigned long *chars )
{
    printf("Counting lines..");
    *names = get_line_count(file, chars);
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

int fill_hash_table( ck_hash_table *table, FILE *file, uint names,
                     unsigned long chars )
{
    // hash the domain names
    int res = hash_from_file(file, table, names, chars);

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

int create_and_fill_table( ck_hash_table **table, FILE *file )
{
    uint names;
    unsigned long chars;
    int res;

    if ((res = count_domain_names(file, &names, &chars)) != 0) {
        fclose(file);
        return ERR_COUNT;
    }

    fseek(file, 0, SEEK_SET);

    *table = ck_create_table(names, destroy_items);

    if (*table == NULL) {
        fprintf(stderr, "Error creating hash table.\n");
        return ERR_TABLE_CREATE;
    }

    if ((res = fill_hash_table(*table, file, names, chars)) != 0) {
		return ERR_FILL;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/

int test_hash_table( char *filename )
{
    printf("Testing hash table...\n\n");

	int res = 0;

	for (int i = 0; i < 10; ++i) {

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
		res = create_and_fill_table(&table, file);

		switch (res) {
			case ERR_FILL:
				ck_destroy_table(&table);
			case ERR_COUNT:
			case ERR_TABLE_CREATE:
				return res;
		}

		printf("\nDone. Result: %d\n\n", res);

		printf("Testing lookup...\n\n");
		res = test_lookup_from_file(table, file);
		printf("\nDone. Result: %d\n\n", res);

		printf("Testing rehash...\n");
		int res_rehash = ck_rehash(table);
		printf("\nDone. Result: %d\n\n", res_rehash);

		printf("Testing lookup...\n\n");
		res = test_lookup_from_file(table, file);
		printf("\nDone. Result: %d\n\n", res);

		ck_destroy_table(&table);
		fclose(file);

		if (res != 0) break;

	}

    return res;
}

/*----------------------------------------------------------------------------*/

int start_server( char *filename )
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
    uint res = create_and_fill_table(&table, file);

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
