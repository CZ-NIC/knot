/**
 * @todo Do not hash the string with the ending '\0'.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "cuckoo-hash-table.h"
#include "dns-simple.h"
#include "bitset.h"
#include "socket-manager.h"

//#define TEST_DEBUG
//#define TEST_LOOKUP
//#define TEST_OUTPUT

static const uint ERR_ARG = 1;
static const uint ERR_FILE_OPEN = 2;
static const uint ERR_FILE_READ = 3;
static const uint ERR_TABLE_CREATE = 4;
static const uint ERR_INSERT = 5;
static const uint ERR_LOOKUP = 6;
static const uint ERR_ALLOC_ITEMS = 7;
static const uint ERR_FIND = 8;

static const uint BUF_SIZE = 20;
static const uint ARRAY_SIZE = 500;

static const unsigned short PORT = 53535;
static const uint THREAD_COUNT = 2;

/*----------------------------------------------------------------------------*/
// macro for hash table types

#define CK_KEY_TYPE (char *)
#define CK_VALUE_TYPE (char *)

/*----------------------------------------------------------------------------*/

// global var for counting collisions
unsigned long collisions = 0;

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
#ifdef TEST_DEBUG
        printf("Allocating buffer\n");
#endif
		// allocate some buffer
		buf_size = BUF_SIZE;
		buffer = (char *)malloc(buf_size * sizeof(char));

		if (buffer == NULL) {
			fprintf(stderr, "Allocation failed.\n");
			return -1;
		}
#ifdef TEST_DEBUG
        printf("Done\n");
#endif
        ch = fgetc(file);

        while (ch != ' ' && ch != '\n' && ch != EOF) {
//#ifdef TEST_DEBUG
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

#ifdef TEST_DEBUG
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
#ifdef TEST_DEBUG
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

#ifdef TEST_DEBUG
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
            key_size = dnss_wire_dname_size(buffer);
            key = malloc(dnss_wire_dname_size(buffer));
            if (dnss_dname_to_wire(buffer, key, key_size) != 0) {
                dnss_destroy_rr(&value);
                free(buffer);
                free(key);
                return ERR_INSERT;
            }

#ifdef TEST_DEBUG
            if (line % 100000 == 1) {
                fprintf(stderr, "Inserting item number %u, key: %s..\n",
                        line, key);
                //hex_print(key, dnss_wire_dname_size(buffer));
            }
#endif

            if ((res = ck_insert_item(table, key,
                                      dnss_wire_dname_size(buffer) - 1,
                                      value, &collisions)) != 0) {
				fprintf(stderr, "\nInsert item returned %d.\n", res);
                dnss_destroy_rr(&value);
                free(key);
				free(buffer);
				return ERR_INSERT;
			}

#ifdef TEST_DEBUG
            if (line % 100000 == 0) {
                fprintf(stderr, "Done, %lu collisions so far.\n", collisions);
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
    const ck_hash_table_item *res;

	while (ch != EOF) {
		buf_i = 0;

#ifdef TEST_DEBUG
        printf("Allocating buffer\n");
#endif

		// allocate some buffer
		buf_size = BUF_SIZE;
		buffer = (char *)malloc(buf_size * sizeof(char));

		if (buffer == NULL) {
			fprintf(stderr, "Allocation failed.\n");
			return -1;
		}
#ifdef TEST_DEBUG
        printf("Done\n");
#endif
		ch = fgetc(file);

        while ((ch != ' ' && ch != '\n') && ch != EOF) {
#ifdef TEST_DEBUG
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

#ifdef TEST_DEBUG
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

		//printf("Read domain name %s, inserting...\n", buffer);

		if (buf_i > 0) {
			// find domain name

            uint key_size = dnss_wire_dname_size(buffer);
            char *key = malloc(key_size);
            if (dnss_dname_to_wire(buffer, key, key_size) != 0) {
                free(buffer);
                free(key);
                return -1;
            }


            if ((res = ck_find_item(table, key,
                                    dnss_wire_dname_size(buffer) - 1)) == NULL
                || strncmp(res->key, key, dnss_wire_dname_size(buffer) - 1) != 0 ) {
                fprintf(stderr, "\nItem with key %s not found.\n", buffer);
                free(key);
                free(buffer);
                return ERR_FIND;
            }

#if defined TEST_DEBUG || defined TEST_LOOKUP
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

int test_bitset()
{
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
    BITSET_DESTROY(&bitset);

	printf("There were %u errors.\n", err);
	return 0;
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
#if defined(TEST_DEBUG) || defined(TEST_OUTPUT)
    printf("answer_request() called with query size %d.\n", size);
    hex_print(query_wire, size);
#endif

    dnss_packet *query = dnss_parse_query(query_wire, size);
    if (query == NULL) {
        return;
    }

#if defined(TEST_DEBUG) || defined(TEST_OUTPUT)
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
#if defined(TEST_DEBUG) || defined(TEST_OUTPUT)
        printf("Requested name not found, returning empty response.\n");
#endif
        if (dnss_create_response(query, NULL, 0, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return;
        }
    } else {
#if defined(TEST_DEBUG) || defined(TEST_OUTPUT)
        printf("Requested name found.\n");
#endif
        if (dnss_create_response(query, (dnss_rr *)item->value,
                                 1, &response) != 0) {
            dnss_destroy_packet(&query);
            dnss_destroy_packet(&response);
            return;
        }
    }

#if defined(TEST_DEBUG) || defined(TEST_OUTPUT)
    printf("Response ID: %u\n", response->header.id);
#endif

    if (dnss_wire_format(response, response_wire, response_size) != 0) {
#if defined(TEST_DEBUG) || defined(TEST_OUTPUT)
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

#if defined(TEST_DEBUG) || defined(TEST_OUTPUT)
    printf("Returning response of size: %u.\n", *response_size);
#endif

    dnss_destroy_packet(&query);
    dnss_destroy_packet(&response);
}

/*----------------------------------------------------------------------------*/

int main( int argc, char **argv )
{
	FILE *file;
	uint names;
	int res;
	unsigned long chars;

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

	if (names == -1) {
		fprintf(stderr, "Error reading domain names from file.\n");
		return ERR_FILE_READ;
	}

#ifdef TEST_DEBUG
    printf("Domains read: %d.\n", names);
#endif

    table = ck_create_table(names, destroy_items);

	if (table == NULL) {
		fprintf(stderr, "Error creating hash table.\n");
		return ERR_TABLE_CREATE;
	}

	fseek(file, 0, SEEK_SET);

	// hash the domain names
    res = hash_from_file(file, table, names, chars);

	if (res == 0) {
        printf("Successful.\n");
		printf("Number of items in the buffer: %u\n", table->buf_i + 1);
	} else {
		fprintf(stderr, "Error inserting names to the hash table.\n");
	}

	fseek(file, 0, SEEK_SET);

    // testing lookup
	res = test_lookup_from_file(table, file);

    if (res != 0) {
        ck_destroy_table(&table);
        return res;
    }

    // launch socket manager for listening
    sm_manager *manager = sm_create(PORT, THREAD_COUNT, answer_request);
    if (manager == NULL) {
        ck_destroy_table(&table);
        return -1;
    }

    printf("Starting socket manager...\n");
    sm_start(manager);

    // can I do this?? pointer to the manager is still in the threads
    sm_destroy(&manager);

    ck_destroy_table(&table);

    return 0;
}
