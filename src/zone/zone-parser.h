/*!
 * @file zone-parser.h
 *
 * Provides interface to zone parsing.
 *
 * As of now, it only provides one API function for parsing a special testing
 * file. Later a generic API for parsing any kind of zone file should be
 * provided.
 *
 * @todo Cosider creating whole zone and filling it prior to adding to zone
 *       database. Or create some API of zone database which will allow to do
 *       this and adds the zone only when told to.
 */

#ifndef ZONE_PARSER
#define ZONE_PARSER

#include "zone-database.h"

/*----------------------------------------------------------------------------*/
/*!
 * @brief Parses a special testing format of zone file and saves the data to the
 *        given database.
 *
 * The zone is created and added to the database prior to filling with data.
 * Zone data are added one-by-one when the zone is already in the database.
 *
 * The testing zone file should contain each domain name on a separate row and
 * followed by a space. Everything after the space is ignored.
 */
int zp_parse_zone( const char *filename, zdb_database *database );

#endif // ZONE_PARSER
