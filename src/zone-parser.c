#include "zone-parser.h"
#include "dns-simple.h"
#include "common.h"
#include <stdio.h>
#include <assert.h>

/*----------------------------------------------------------------------------*/

static const uint BUF_SIZE = 25;
static const int ERR_FILE_OPEN = -1;
static const int ERR_PARSE = -2;
static const int ERR_INSERT = -3;
static const int ERR_ALLOC = -4;
static const int ERR_COUNT = -5;
static const int ERR_ZONE_CREATE = -6;

#define ERR_ZONE_CREATE_FAILED fprintf(stderr, "Zone could not be created.\n")
#define ERR_PARSING_FAILED fprintf(stderr, "Zone parsing failed.\n")

/*----------------------------------------------------------------------------*/

uint zp_get_line_count( FILE *file )
{
    char ch = '\0';
    uint c = 0;

    while (ch != EOF) {
        ch = fgetc(file);
        if (ch == '\n') {
            c++;
        }
    }

    return c;
}

/*----------------------------------------------------------------------------*/

int zp_resize_buffer( char **buffer, uint *buf_size, int new_size,
                      int item_size )
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

int zp_test_count_domain_names( FILE *file, uint *names )
{
#ifdef ZP_DEBUG
    printf("Counting lines..");
#endif
    *names = zp_get_line_count(file);
#ifdef ZP_DEBUG
    printf("%u\n", *names);
#endif

    if (*names == -1) {
        fprintf(stderr, "Error reading domain names from file.\n");
        return -1;
    }

#ifdef ZP_DEBUG
    printf("Domains read: %d.\n", *names);
#endif

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_test_read_dname( char **buffer, uint *buf_i, FILE* file,
                                  char *ch )
{
    // allocate some buffer
#ifdef ZP_PARSE_DEBUG
        printf("Allocating buffer\n");
#endif
    uint buf_size = BUF_SIZE;
    *buffer = (char *)malloc(buf_size * sizeof(char));

    if (*buffer == NULL) {
        ERR_ALLOC_FAILED;
        return -1;
    }
#ifdef ZP_PARSE_DEBUG
    printf("Done\n");
#endif
    *ch = fgetc(file);

    *buf_i = 0;

    while (*ch != ' ' && *ch != '\n' && *ch != EOF) {
        *buffer[*buf_i] = *ch;
        (*buf_i)++;

        // if the buffer is not big enough, resize
        if ((*buf_i >= buf_size)
            && (zp_resize_buffer(buffer, &buf_size,
                             buf_size * 2, sizeof(char)) != 0)) {
            free(*buffer);
            *buffer = NULL;
            return -1;
        }

        *ch = fgetc(file);
    }

    *buffer[*buf_i] = '\0';

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_test_parse_file( zdb_database *database,
                        const dnss_dname_wire *zone_name, FILE *file )
{
    int res;
    uint key_size;
    char ch = '\0';
    char *buffer, *key;
    dnss_rr *rr;
    int line = 0;

    while (ch != EOF) {
        uint buf_i;
        if (zp_test_read_dname(&buffer, &buf_i, file, &ch) != 0) {
            return -1;
        }

        line++;

        // read rest of the characters (not interesting)
        while (ch != '\n' && ch != EOF) {
            ch = fgetc(file);
        }

#ifdef ZP_PARSE_DEBUG
        printf("Read domain name %s, inserting...\n", buffer);
#endif
        if (buf_i > 0) {

#ifdef ZP_PARSE_DEBUG
            printf("Creating RR with the given owner name.\n");
#endif
            rr = dnss_create_rr(buffer);
            if (rr == NULL) {
                ERR_ALLOC_FAILED;
                free(buffer);
                return ERR_INSERT;
            }

#ifdef ZP_PARSE_DEBUG
            printf("Creating Zone Node with the given RR.\n");
#endif
            zn_node *node = zn_create(1);
            if (node == NULL) {
                ERR_ALLOC_FAILED;
                free(buffer);
                dnss_destroy_rr(&rr);
                return ERR_INSERT;
            }
            zn_add_rr(node, rr);

            // use the domain name from the RR for inserting (already converted)
            key_size = dnss_wire_dname_size(&buffer);
            key = malloc(key_size);
            if (key == NULL) {
                ERR_ALLOC_FAILED;
                dnss_destroy_rr(&rr);
                return ERR_INSERT;
            }
            memcpy(key, rr->owner, key_size);

#ifdef ZP_PARSE_DEBUG
            if (line % 100000 == 1) {
                fprintf(stderr, "Inserting item number %u, key:\n", line);
                hex_print(key, key_size);
            }
#endif

            if ((res = zdb_insert_name(database, *zone_name, key, node)) != 0) {
                fprintf(stderr, "\nInsert item returned %d.\n", res);
                if (res < 0) {
                    dnss_destroy_rr(&rr);
                    free(key);
                }
                free(buffer);
                return ERR_INSERT;
            }

#ifdef ZP_PARSE_DEBUG
            if (line % 100000 == 0) {
                fprintf(stderr, "Done.\n");
            }
#endif
        }
        free(buffer);
        buffer = NULL;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_test_parse_zone( const char *filename, zdb_database *database )
{

    char *DEFAULT_ZONE_NAME = "cz";

    // open the zone file
    #ifdef ZP_DEBUG
    printf("Opening file...");
    #endif
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        fprintf(stderr, "Can't open file: %s.\n", filename);
        return ERR_FILE_OPEN;
    }
    #ifdef ZP_DEBUG
    printf("Done.\n\n");
    #endif

    // determine name of the zone (and later other things)
    // for now lets assume there is only one zone and use the default name (cz)
    int name_size = dnss_wire_dname_size(&DEFAULT_ZONE_NAME);
    dnss_dname_wire zone_name = malloc(name_size);

    if (zone_name == NULL) {
        ERR_ALLOC_FAILED;
        fclose(file);
        return ERR_ALLOC;
    }

    int res = dnss_dname_to_wire(DEFAULT_ZONE_NAME, zone_name, name_size);
    assert(res == 0);

    uint names;
    // count distinct domain names in the zone file
    if ((res = zp_test_count_domain_names(file, &names)) != 0) {
        fclose(file);
        free(zone_name);
        return ERR_COUNT;
    }

    // create a new zone in the zone database
    if ((res = zdb_create_zone(database, zone_name, names)) != 0) {
        fclose(file);
        free(zone_name);
        ERR_ZONE_CREATE_FAILED;
        return ERR_ZONE_CREATE;
    }

    fseek(file, 0, SEEK_SET);

    // parse the zone file and fill in the zone
    if ((res == zp_test_parse_file(database, &zone_name, file)) != 0) {
        // is this necessary?
        zdb_remove_zone(database, zone_name);
        free(zone_name);
        fclose(file);
        ERR_PARSING_FAILED;
        return ERR_PARSE;
    }

    free(zone_name);
    fclose(file);

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_count_domain_names( FILE *file, uint *names )
{
    return zp_test_count_domain_names(file, names);
}

/*----------------------------------------------------------------------------*/

int zp_parse_zonefile( zdb_database *database, dnss_dname_wire *zone_name,
                       FILE *file )
{
    return zp_test_parse_file(database, zone_name, file);
}

/*----------------------------------------------------------------------------*/

int zp_parse_zone( const char *filename, zdb_database *database )
{
    return zp_test_parse_zone(filename, database);
}
