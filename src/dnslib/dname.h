#ifndef _CUTEDNS_DNAME_H
#define _CUTEDNS_DNAME_H

#include <stdint.h>
#include "common.h"
#include "node.h"

/*----------------------------------------------------------------------------*/

struct dnslib_dname {
	uint8_t *name;	// wire format of a domain name; always ends with 0!!
	uint size;	// is this needed? every dname should end with \0 or pointer
	dnslib_node_t *node;	// NULL if not in zone
};

typedef struct dname dnslib_dname_t;

/*----------------------------------------------------------------------------*/

/*!
 * \todo Possibly useless.
 */
dnslib_dname_t *dnslib_dname_new();

/*!
 * \note \a name must be 0-terminated.
 * \note \a node may be NULL.
 */
dnslib_dname_t *dnslib_dname_new_from_str( char *name, uint size,
										   dnslib_node_t *node );

/*!
 * \note Copies the name.
 */
dnslib_dname_t *dnslib_dname_new_from_wire( uint8_t *name, uint size );

/*!
 * \note Allocates new memory, remember to free it. Returns 0-terminated string.
 */
char *dnslib_dname_to_str( dnslib_dname_t *dname );

/*!
 * \note Frees also the data within the struct.
 */
void dnslib_dname_free( dnslib_dname *dname );



#endif /* _CUTEDNS_DNAME_H */
