#include "zone-parser.h"
#include "dns-simple.h"
#include "common.h"
#include <stdio.h>
#include <assert.h>
#include <ldns/rr.h>
#include <ldns/rdata.h>
#include <ldns/dname.h>
#include <ldns/zone.h>

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

#define ERR_ZONE_CREATE_FAILED log_error("Zone could not be created.\n")
#define ERR_PARSING_FAILED log_error("Zone parsing failed.\n")

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

int zp_test_parse_file( zdb_database *database, ldns_rdf *zone_name,
						FILE *file )
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

		debug_zp_parse("Read domain name %s, inserting...\n", buffer);

        if (buf_i > 0) {
			debug_zp_parse("Creating RR with the given owner name.\n");

            rr = dnss_create_rr(buffer);
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
                dnss_destroy_rr(&rr);
                return ERR_INSERT;
            }

			ldns_rr *r = ldns_rr_new();
			ldns_rr_set_class(r, rr->rrclass);
			ldns_rr_set_type(r, rr->rrtype);
			ldns_rr_set_ttl(r, rr->ttl);
			ldns_rdf *owner = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME,
								strlen(rr->owner) + 1,
								rr->owner);
			ldns_rr_set_owner(r, owner);
			ldns_rdf *rdata = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A,
								rr->rdlength,
								rr->rdata);
			ldns_rr_set_rdf(r, rdata, 0);

			zn_add_rr(node, r);

            // use the domain name from the RR for inserting (already converted)
            key_size = dnss_wire_dname_size(&buffer);
            key = malloc(key_size);
            if (key == NULL) {
                ERR_ALLOC_FAILED;
                dnss_destroy_rr(&rr);
                return ERR_INSERT;
            }
            memcpy(key, rr->owner, key_size);

			debug_zp_parse("Inserting item number %u, key:\n", line);
			debug_zp_parse_hex(key, key_size);

			if ((res = zdb_insert_name(database, zone_name, owner, node)) != 0) {
				debug_zp_parse("\nInsert item returned %d.\n", res);
                if (res < 0) {
                    dnss_destroy_rr(&rr);
                    free(key);
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

    char *DEFAULT_ZONE_NAME = "cz";

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
    int name_size = dnss_wire_dname_size(&DEFAULT_ZONE_NAME);
    dnss_dname_wire zone_name = malloc(name_size);

    if (zone_name == NULL) {
        ERR_ALLOC_FAILED;
        fclose(file);
        return ERR_ALLOC;
    }

    int res = dnss_dname_to_wire(DEFAULT_ZONE_NAME, zone_name, name_size);
    assert(res == 0);

	// create lsdn zone name
	ldns_rdf *zone_name_ldns = ldns_dname_new_frm_data(strlen(zone_name) + 1,
													   zone_name);

    debug_zp("Counting domain names in the file...\n");
    uint names;
    // count distinct domain names in the zone file
    if ((res = zp_test_count_domain_names(file, &names)) != 0) {
        fclose(file);
        free(zone_name);
        return ERR_COUNT;
    }

    debug_zp("Done.\n");
    debug_zp("Creating new zone with name '%s'...\n", zone_name);

    // create a new zone in the zone database
	if ((res = zdb_create_zone(database, zone_name_ldns, names)) != 0) {
        fclose(file);
        free(zone_name);
        ERR_ZONE_CREATE_FAILED;
        return ERR_ZONE_CREATE;
    }

    debug_zp("Done.\n");
    fseek(file, 0, SEEK_SET);
    debug_zp("Parsing the zone file...\n");

    // parse the zone file and fill in the zone
	if ((res = zp_test_parse_file(database, zone_name_ldns, file)) != 0) {
        // is this necessary?
		zdb_remove_zone(database, zone_name_ldns);
        free(zone_name);
        fclose(file);
        ERR_PARSING_FAILED;
        return ERR_PARSE;
    }

    debug_zp("Done.\n");
    free(zone_name);

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
	s = ldns_zone_new_frm_fp_l(&zone, file, NULL, 0, LDNS_RR_CLASS_IN, &line);

	fclose(file);

	if (s != LDNS_STATUS_OK) {
		log_error("Error parsing zone file %s.\nldns returned: %s on line %d\n",
				filename, ldns_get_errorstr_by_id(s), line);
		return -1;
	}

	return zdb_add_zone(database, zone);
}

/*----------------------------------------------------------------------------*/

int zp_parse_zone( const char *filename, zdb_database *database )
{
	//return zp_test_parse_zone(filename, database);
	return zp_parse_zonefile_bind(filename, database);
}
