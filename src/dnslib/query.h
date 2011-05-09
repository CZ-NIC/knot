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
int dnslib_query_dnssec_requested(const dnslib_packet_t *query);

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
int dnslib_query_nsid_requested(const dnslib_packet_t *query);

//int dnslib_query_set_qname(dnslib_packet_t *query, const dnslib_dname_t *qname);

//int dnslib_query_set_qtype(dnslib_packet_t *query, uint16_t qtype);

//int dnslib_query_set_qclass(dnslib_packet_t *query, uint16_t qclass);

int dnslib_query_init(dnslib_packet_t *query);

int dnslib_query_set_question(dnslib_packet_t *query,
                              const dnslib_question_t *question);

#endif /* _KNOT_DNSLIB_QUERY_H_ */

/*! @} */
