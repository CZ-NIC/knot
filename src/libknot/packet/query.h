/*!
 * \file query.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief API for manipulating queries.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KNOT_QUERY_H_
#define _KNOT_QUERY_H_

#include <stdint.h>
#include <string.h>

#include "packet/packet.h"
#include "dname.h"
#include "rrset.h"
#include "edns.h"

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

int knot_query_init(knot_packet_t *query);

int knot_query_set_question(knot_packet_t *query,
                              const knot_question_t *question);

int knot_query_set_opcode(knot_packet_t *query, uint8_t opcode);

/*!
 * \brief Adds a RRSet to the Authority section of the query.
 *
 * \param query Query to add the RRSet into.
 * \param rrset RRSet to be added.
 *
 * \retval KNOT_EOK if successful, or the RRSet was already in the query.
 * \retval KNOT_ENOMEM
 * \retval KNOT_ESPACE
 */
int knot_query_add_rrset_authority(knot_packet_t *query,
                                   const knot_rrset_t *rrset);


#endif /* _KNOT_QUERY_H_ */

/*! @} */
