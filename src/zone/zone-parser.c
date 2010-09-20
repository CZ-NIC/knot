#include "zone-parser.h"
#include "common.h"
#include <stdio.h>
#include <assert.h>
#include <ldns/ldns.h>

/*----------------------------------------------------------------------------*/

#if defined(ZP_DEBUG) || defined(ZP_DEBUG_PARSE)
#include "cuckoo-test.h"
#endif

static const uint BUF_SIZE = 25;
static const int ERR_FILE_OPEN = -1;
static const int ERR_PARSE = -2;
static const int ERR_INSERT = -3;
static const int ERR_ALLOC = -4;
static const int ERR_COUNT = -5;
static const int ERR_ZONE_CREATE = -6;

// default test values
static const uint16_t RRTYPE_DEFAULT       = 1;		// A
static const uint16_t RRCLASS_DEFAULT      = 1;		// IN
static const uint32_t TTL_DEFAULT          = 3600;
static const unsigned int RDLENGTH_DEFAULT = 4;
static const uint8_t RDATA_DEFAULT[4] = { 127, 0, 0, 1 };

#define ERR_ZONE_CREATE_FAILED log_error("Zone could not be created.\n")
#define ERR_PARSING_FAILED log_error("Zone parsing failed.\n")

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
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
        ERR_ALLOC_FAILED;
        return -1;
    }
    *buffer = new_buf;
    *buf_size = new_size;

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_test_count_domain_names( FILE *file, uint *names )
{
    debug_zp("Counting lines..");
    *names = zp_get_line_count(file);
    debug_zp("%u\n", *names);

    if (*names == -1) {
		log_error("Error reading domain names from file.\n");
        return -1;
    }

    debug_zp("Domains read: %d.\n", *names);

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_test_read_dname( char **buffer, uint *buf_i, FILE* file,
                        char *ch )
{
    // allocate some buffer
	debug_zp_parse("Allocating buffer\n");

    uint buf_size = BUF_SIZE;
    *buffer = (char *)malloc(buf_size * sizeof(char));

    if (*buffer == NULL) {
        ERR_ALLOC_FAILED;
        return -1;
    }

	debug_zp_parse("Done\n");
    *ch = fgetc(file);

    *buf_i = 0;

    while (*ch != ' ' && *ch != '\n' && *ch != EOF) {
        (*buffer)[*buf_i] = *ch;
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

    (*buffer)[*buf_i] = '\0';


    return 0;
}

/*----------------------------------------------------------------------------*/

ldns_rr *zp_test_create_rr( char *buffer )
{
	ldns_rr *rr = ldns_rr_new();
	if (rr == NULL) {
		return NULL;
	}

	ldns_rdf *rdata = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, RDLENGTH_DEFAULT,
											RDATA_DEFAULT);
	if (rdata == NULL) {
		free (rr);
		return NULL;
	}

	ldns_rdf *owner = ldns_dname_new_frm_str(buffer);
	ldns_rr_set_owner(rr, owner);
	ldns_rr_set_class(rr, RRCLASS_DEFAULT);
	ldns_rr_set_type(rr, RRTYPE_DEFAULT);
	ldns_rr_set_ttl(rr, TTL_DEFAULT);
	ldns_rr_push_rdf(rr, rdata);

	return rr;
}

/*----------------------------------------------------------------------------*/

int zp_test_parse_file( zdb_database *database, ldns_rdf *zone_name,
						FILE *file )
{
    int res;
    char ch = '\0';
	char *buffer;
	ldns_rr *rr;
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

		debug_zp_parse("Read domain name %s, inserting...\n", buffer);

        if (buf_i > 0) {
			debug_zp_parse("Creating RR with the given owner name.\n");

			rr = zp_test_create_rr(buffer);
            if (rr == NULL) {
                ERR_ALLOC_FAILED;
                free(buffer);
                return ERR_INSERT;
            }

			debug_zp_parse("Creating Zone Node with the given RR.\n");

            zn_node *node = zn_create(1);
            if (node == NULL) {
                ERR_ALLOC_FAILED;
                free(buffer);
				ldns_rr_free(rr);
                return ERR_INSERT;
            }

			zn_add_rr(node, rr);

			if ((res = zdb_insert_name(database, zone_name, node)) != 0) {
				debug_zp_parse("\nInsert item returned %d.\n", res);
                if (res < 0) {
					zn_destroy(&node);
                }
                free(buffer);
                return ERR_INSERT;
            }

			debug_zp_parse("Done.\n");
        }
        free(buffer);
        buffer = NULL;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_test_parse_zone( const char *filename, zdb_database *database )
{

	const char *DEFAULT_ZONE_NAME = "cz";

    // open the zone file
    debug_zp("Opening file...\n");
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
		log_error("Can't open file: %s.\n", filename);
        return ERR_FILE_OPEN;
    }

    debug_zp("Done.\n");

    // determine name of the zone (and later other things)
    // for now lets assume there is only one zone and use the default name (cz)
	ldns_rdf *zone_name = ldns_dname_new_frm_str(DEFAULT_ZONE_NAME);

    if (zone_name == NULL) {
        ERR_ALLOC_FAILED;
        fclose(file);
        return ERR_ALLOC;
    }

	int res;

    debug_zp("Counting domain names in the file...\n");
    uint names;
    // count distinct domain names in the zone file
    if ((res = zp_test_count_domain_names(file, &names)) != 0) {
        fclose(file);
        free(zone_name);
        return ERR_COUNT;
    }

    debug_zp("Done.\n");
	debug_zp("Creating new zone with name '%s'...\n", ldns_rdf2str(zone_name));

    // create a new zone in the zone database
	if ((res = zdb_create_zone(database, zone_name, names)) != 0) {
        fclose(file);
		ldns_rdf_deep_free(zone_name);
        ERR_ZONE_CREATE_FAILED;
        return ERR_ZONE_CREATE;
    }

    debug_zp("Done.\n");
    fseek(file, 0, SEEK_SET);
    debug_zp("Parsing the zone file...\n");

    // parse the zone file and fill in the zone
	if ((res = zp_test_parse_file(database, zone_name, file)) != 0) {
        // is this necessary?
		zdb_remove_zone(database, zone_name);
		ldns_rdf_deep_free(zone_name);
        fclose(file);
        ERR_PARSING_FAILED;
        return ERR_PARSE;
    }

    debug_zp("Done.\n");
	ldns_rdf_deep_free(zone_name);

#ifdef ZP_DEBUG
	//debug_zp("\nTesting lookup..\n");
	//test_lookup_from_file(database->head->zone, file);
#endif

    fclose(file);

    return 0;
}

/*----------------------------------------------------------------------------*/

int zp_parse_zonefile_bind( const char *filename, zdb_database *database )
{
	debug_zp("Opening file...\n");
	FILE *file = fopen(filename, "r");

	if (file == NULL) {
		log_error("Can't open file: %s.\n", filename);
		return ERR_FILE_OPEN;
	}

	debug_zp("Done.\n");

	ldns_zone *zone;
	int line = 0;
	ldns_status s;
	log_info("\nParsing zone file %s...\n", filename);
	s = ldns_zone_new_frm_fp_l(&zone, file, NULL, 0, LDNS_RR_CLASS_IN, &line);
	log_info("Done.\n");

	fclose(file);

	if (s != LDNS_STATUS_OK) {
		log_error("Error parsing zone file %s.\nldns returned: %s on line %d\n",
				filename, ldns_get_errorstr_by_id(s), line);
		return -1;
	}

	return zdb_add_zone(database, zone);
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

int zp_parse_zone( const char *filename, zdb_database *database )
{
	//return zp_test_parse_zone(filename, database);
	return zp_parse_zonefile_bind(filename, database);
}
