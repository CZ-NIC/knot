#ifndef _CUTEDNS_DNAME_H
#define _CUTEDNS_DNAME_H

#include <stdint.h>
#include "common.h"

struct dnslib_node;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for representing a domain name.
 *
 * Stores the domain name in wire format.
 *
 * \todo Consider restricting to FQDN only (see dnslib_dname_new_from_str()).
 */
struct dnslib_dname {
	uint8_t *name;	/*!< Wire format of the domain name. */
	/*!
	 * \brief Size of the domain name in octets.
	 * \todo Is this needed? Every dname should end with \0 or pointer.
	 */
	uint size;
	struct dnslib_node *node;	/*!< Zone node the domain name belongs to. */
};

typedef struct dnslib_dname dnslib_dname_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Creates empty dname structure (no name, no owner node).
 *
 * \return Newly allocated and initialized dname structure.
 * \todo Possibly useless.
 */
dnslib_dname_t *dnslib_dname_new();

/*!
 * \brief Creates a dname structure from domain name given in presentation
 *        format.
 *
 * \param name Domain name in presentation format (labels separated by dots).
 * \param size Size of the domain name (count of characters with all dots).
 * \param node Zone node the domain name belongs to. Set to NULL if not
 *             applicable.
 *
 * The resulting domain name is stored in wire format and ALWAYS ENDS WITH 0,
 * e.g. is a FQDN even if the given domain name was not.
 *
 * \return Newly allocated and initialized dname structure representing the
 *         given domain name.
 *
 * \todo Check if the FQDN issue is OK.
 */
dnslib_dname_t *dnslib_dname_new_from_str( char *name, uint size,
										   struct dnslib_node *node );

/*!
 * \brief Creates a dname structure from domain name given in wire format.
 *
 * \param name Domain name in wire format.
 * \param size Size of the domain name in octets.
 * \param node Zone node the domain name belongs to. Set to NULL if not
 *             applicable.
 *
 * \return Newly allocated and initialized dname structure representing the
 *         given domain name.
 *
 * \note The name is copied into the structure.
 * \note If the given name is not a FQDN, the result will be neither. This
 *       does not correspond to the behaviour of dnslib_dname_new_from_str().
 * \todo Address the FQDN issue.
 */
dnslib_dname_t *dnslib_dname_new_from_wire( uint8_t *name, uint size,
											struct dnslib_node *node );

/*!
 * \brief Converts the given domain name to string representation.
 *
 * \param dname Domain name to be converted.
 *
 * \return 0-terminated string representing the given domain name in
 *         presentation format.
 * \note Allocates new memory, remember to free it.
 */
char *dnslib_dname_to_str( const dnslib_dname_t *dname );

/*!
 * \brief Returns the domain name in wire format.
 *
 * \param dname Domain name.
 *
 * \return Wire format of the domain name.
 */
const uint8_t *dnslib_dname_name( const dnslib_dname_t *dname );

/*!
 * \brief Returns size of the given domain name.
 *
 * \param dname Domain name to get the size of.
 *
 * \return Size of the domain name in wire format in octets.
 */
uint dnslib_dname_size( const dnslib_dname_t *dname );

/*!
 * \brief Returns the zone node the domain name belongs to.
 *
 * \param dname Domain name to get the zone node of.
 *
 * \return Zone node the domain name belongs to or NULL if none.
 */
const struct dnslib_node *dnslib_dname_node( const dnslib_dname_t *dname );

/*!
 * \brief Destroys the given domain name.
 *
 * \param dname Domain name to be destroyed.
 *
 * \note Frees also the data within the struct.
 */
void dnslib_dname_free( dnslib_dname_t *dname );

#endif /* _CUTEDNS_DNAME_H */
