#ifndef CUCKOO_TEST
#define CUCKOO_TEST

#include "cuckoo-hash-table.h"
#include <stdio.h>

/*----------------------------------------------------------------------------*/

int test_hash_table( char *filename );

int start_server( char *filename );

int test_lookup_from_file( ck_hash_table *table, FILE *file );

/*----------------------------------------------------------------------------*/

#endif
