/*!
 * \file response.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief API for response manipulation.
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

#ifndef _KNOT_response_H_
#define _KNOT_response_H_

#include <stdint.h>
#include <string.h>

#include "packet/packet.h"

#include "dname.h"
#include "rrset.h"
#include "edns.h"

/*!
 * \brief Default maximum DNS response size
 *
 * This size must be supported by all servers and clients.
 */
static const short KNOT_MAX_RESPONSE_SIZE = 512;

/*----------------------------------------------------------------------------*/
int knot_response_init(knot_packet_t *response);

/*!
 * \brief Initializes response from the given query.
 *
 * Copies the header, Changes QR bit to 1, copies the Question section and
 * stores pointer to the query packet structure in the response packet
 * structure.
 *
 * \warning Never free the query packet structure after calling this function,
 *          it will be freed when the response structure is freed.
 *
 * \param response Packet structure representing the response.
 * \param query Packet structure representing the query.
 *
 * \retval KNOT_EOK
 */
int knot_response_init_from_query(knot_packet_t *response,
                                  knot_packet_t *query,
                                  int copy_question);

/*!
 * \brief Clears the response structure for reuse.
 *
 * After call to this function, the response will be in the same state as if
 * knot_response_new() was called. The maximum wire size is retained.
 *
 * \param response Response structure to clear.
 *
 * \todo Replace the use of this function with something else maybe?
 */
void knot_response_clear(knot_packet_t *resp, int clear_question);

/*!
 * \brief Sets the OPT RR of the response.
 *
 * This function also allocates space for the wireformat of the response, if
 * the payload in the OPT RR is larger than the current maximum size of the
 * response and copies the current wireformat over to the new space.
 *
 * \note The contents of the OPT RR are copied.
 *
 * \param resp Response to set the OPT RR to.
 * \param opt_rr OPT RR to set.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 *
 * \todo Needs test.
 */
int knot_response_add_opt(knot_packet_t *resp,
                            const knot_opt_rr_t *opt_rr,
                            int override_max_size,
                            int add_nsid);

/*!
 * \brief Adds a RRSet to the Answer section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 * \param check_duplicates Set to <> 0 if the RRSet should not be added to the
 *                         response in case it is already there.
 * \param compr_cs Set to <> 0 if dname compression should use case sensitive
 *                 comparation. Set to 0 otherwise.
 *
 * \retval KNOT_EOK if successful, or the RRSet was already in the answer.
 * \retval KNOT_ENOMEM
 * \retval KNOT_ESPACE
 */
int knot_response_add_rrset_answer(knot_packet_t *response,
                                   knot_rrset_t *rrset, int tc,
                                   int check_duplicates, int compr_cs,
                                   int rotate);

/*!
 * \brief Adds a RRSet to the Authority section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 * \param check_duplicates Set to <> 0 if the RRSet should not be added to the
 *                         response in case it is already there.
 * \param compr_cs Set to <> 0 if dname compression should use case sensitive
 *                 comparation. Set to 0 otherwise.
 *
 * \retval KNOT_EOK if successful, or the RRSet was already in the answer.
 * \retval KNOT_ENOMEM
 * \retval KNOT_ESPACE
 */
int knot_response_add_rrset_authority(knot_packet_t *response,
                                      knot_rrset_t *rrset, int tc,
                                      int check_duplicates, int compr_cs,
                                      int rotate);

/*!
 * \brief Adds a RRSet to the Additional section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 * \param check_duplicates Set to <> 0 if the RRSet should not be added to the
 *                         response in case it is already there.
 * \param compr_cs Set to <> 0 if dname compression should use case sensitive
 *                 comparation. Set to 0 otherwise.
 *
 * \retval KNOT_EOK if successful, or the RRSet was already in the answer.
 * \retval KNOT_ENOMEM
 * \retval KNOT_ESPACE
 */
int knot_response_add_rrset_additional(knot_packet_t *response,
                                       knot_rrset_t *rrset, int tc,
                                       int check_duplicates, int compr_cs,
                                       int rotate);

/*!
 * \brief Sets the RCODE of the response.
 *
 * \param response Response to set the RCODE in.
 * \param rcode RCODE to set.
 */
void knot_response_set_rcode(knot_packet_t *response, short rcode);

/*!
 * \brief Sets the AA bit of the response to 1.
 *
 * \param response Response in which the AA bit should be set.
 */
void knot_response_set_aa(knot_packet_t *response);

/*!
 * \brief Sets the TC bit of the response to 1.
 *
 * \param response Response in which the TC bit should be set.
 */
void knot_response_set_tc(knot_packet_t *response);

/*!
 * \brief Adds NSID option to the response.
 *
 * \param response Response to add the NSID option into.
 * \param data NSID data.
 * \param length Size of NSID data in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
int knot_response_add_nsid(knot_packet_t *response, const uint8_t *data,
                             uint16_t length);

int knot_response_add_wildcard_node(knot_packet_t *response,
                                    const knot_node_t *node,
                                    const knot_dname_t *sname);

#endif /* _KNOT_response_H_ */

/*! @} */
