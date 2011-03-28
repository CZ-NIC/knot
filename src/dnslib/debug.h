/*!
 * \file descriptor.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Functions for debug output of dnslib structures.
 *
 * \addtogroup dnslib
 * @{
 */
#ifndef _KNOT_DNSLIB_DEBUG_H_
#define _KNOT_DNSLIB_DEBUG_H_

#include <stdint.h>
#include "dnslib.h"

/*!
 * \brief Dumps RDATA of the given type.
 *
 * This function is empty if neither DNSLIB_ZONE_DEBUG nor DNSLIB_RDATA_DEBUG
 * is defined.
 *
 * \param rdata RDATA to dump.
 * \param type Type of the RDATA (needed to properly parse the RDATA).
 * \param loaded_zone Set to <> 0 if the RDATA is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void dnslib_rdata_dump(dnslib_rdata_t *rdata, uint32_t type, char loaded_zone);

/*!
 * \brief Dumps RRSet.
 *
 * This function is empty if neither DNSLIB_ZONE_DEBUG nor DNSLIB_RRSET_DEBUG
 * is defined.
 *
 * \param rrset RRSet to dump.
 * \param loaded_zone Set to <> 0 if the RRSet is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void dnslib_rrset_dump(dnslib_rrset_t *rrset, char loaded_zone);

/*!
 * \brief Dumps zone node.
 *
 * This function is empty if neither DNSLIB_ZONE_DEBUG nor DNSLIB_NODE_DEBUG
 * is defined.
 *
 * \param node Node to dump.
 * \param loaded_zone Set to <> 0 if the node is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void dnslib_node_dump(dnslib_node_t *node, void *loaded_zone);

/*!
 * \brief Dumps the whole zone.
 *
 * This function is empty if DNSLIB_ZONE_DEBUG is not defined.
 *
 * \param zone Zone to dump.
 * \param loaded_zone Set to <> 0 if the node is part of a zone loaded into
 *                    the server. Set to 0 otherwise.
 */
void dnslib_zone_dump(dnslib_zone_t *zone, char loaded_zone);

#endif

/*! @} */
