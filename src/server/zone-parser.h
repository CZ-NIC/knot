/*!
 * @todo Cosider creating whole zone and filling it prior to adding to zone
 *       database. Or create some API of zone database which will allow to do
 *       this and adds the zone only when told to.
 */

#ifndef ZONE_PARSER
#define ZONE_PARSER

#include "zone-database.h"

/*----------------------------------------------------------------------------*/

int zp_parse_zone( const char *filename, zdb_database *database );

#endif // ZONE_PARSER
