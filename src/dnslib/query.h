/*!
 * \file query.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief API for manipulating queries.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_QUERY_H_
#define _KNOT_DNSLIB_QUERY_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/packet.h"
#include "dnslib/dname.h"
#include "dnslib/rrset.h"
#include "dnslib/edns.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if DNSSEC was requested in the query (i.e. the DO bit was set).
 *
 * \param query Packet where the parsed query is stored.
 *
 * \retval 0 if the DO bit was not set in the query, or the query is not yet
 *         parsed.
 * \retval > 0 if DO bit was set in the query.
 */
int knot_query_dnssec_requested(const knot_packet_t *query);

/*!
 * \brief Checks if NSID was requested in the query (i.e. the NSID option was
 *        present in the query OPT RR).
 *
 * \param query Packet where the parsed query is stored.
 *
 * \retval 0 if the NSID option was not present in the query, or the query is
 *         not yet parsed.
 * \retval > 0 if the NSID option was present in the query.
 */
int knot_query_nsid_requested(const knot_packet_t *query);

int knot_query_edns_supported(const knot_packet_t *query);

//int knot_query_set_qname(knot_packet_t *query, const knot_dname_t *qname);

//int knot_query_set_qtype(knot_packet_t *query, uint16_t qtype);

//int knot_query_set_qclass(knot_packet_t *query, uint16_t qclass);

int knot_query_init(knot_packet_t *query);

int knot_query_set_question(knot_packet_t *query,
                              const knot_question_t *question);

int knot_query_set_opcode(knot_packet_t *query, uint8_t opcode);

#endif /* _KNOT_DNSLIB_QUERY_H_ */

/*! @} */
