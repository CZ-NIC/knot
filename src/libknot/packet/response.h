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

#ifndef _KNOT_RESPONSE_H_
#define _KNOT_RESPONSE_H_

#include <stdint.h>
#include <string.h>

#include "libknot/packet/packet.h"

#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/edns.h"

/*!
 * \brief Holds information about compressed domain name.
 *
 * Used only to pass information between functions.
 *
 * \todo This description should be revised and clarified.
 */
struct knot_compr_owner {
	/*!
	 * \brief Place where the name is stored in the wire format of the
	 * packet.
	 */
	uint8_t *wire;
	uint8_t size; /*!< Size of the domain name in bytes. */
	/*! \brief Position of the name relative to the start of the packet. */
	size_t pos;
};

typedef struct knot_compr_owner knot_compr_owner_t;

/*!
 * \brief Holds information about compressed domain names in packet.
 *
 * Used only to pass information between functions.
 *
 * \todo This description should be revised and clarified.
 */
struct knot_compr {
	knot_compr_ptr_t *table;  /*!< Compression table. */
	uint8_t *wire;
	size_t wire_pos;            /*!< Current position in the wire format. */
	knot_compr_owner_t owner; /*!< Information about the current name. */
};

typedef struct knot_compr knot_compr_t;

struct compression_param {
	uint8_t *wire;
	size_t wire_pos;
	knot_compr_ptr_t *compressed_dnames;
};

typedef struct compression_param compression_param_t;

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
int knot_response_init_from_query(knot_packet_t *response, knot_packet_t *query);

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
void knot_response_clear(knot_packet_t *resp);

/*!
 * \brief Sets the OPT RR of the response.
 *
 * This function also allocates space for the wireformat of the response, if
 * the payload in the OPT RR is larger than the current maximum size of the
 * response and copies the current wireformat over to the new space.
 *
 * \note The contents of the OPT RR are copied.
 *
 * \note It is expected that resp.max_size is already set to correct value as
 *       it is impossible to distinguish TCP scenario in this function.
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
 *
 * \retval KNOT_EOK if successful, or the RRSet was already in the answer.
 * \retval KNOT_ENOMEM
 * \retval KNOT_ESPACE
 */
int knot_response_add_rrset_answer(knot_packet_t *response,
                                   knot_rrset_t *rrset, uint32_t flags);

/*!
 * \brief Adds a RRSet to the Authority section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 * \param check_duplicates Set to <> 0 if the RRSet should not be added to the
 *                         response in case it is already there.
 *
 * \retval KNOT_EOK if successful, or the RRSet was already in the answer.
 * \retval KNOT_ENOMEM
 * \retval KNOT_ESPACE
 */
int knot_response_add_rrset_authority(knot_packet_t *response,
                                      knot_rrset_t *rrset, uint32_t flags);

/*!
 * \brief Adds a RRSet to the Additional section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 * \param check_duplicates Set to <> 0 if the RRSet should not be added to the
 *                         response in case it is already there.
 *
 * \retval KNOT_EOK if successful, or the RRSet was already in the answer.
 * \retval KNOT_ENOMEM
 * \retval KNOT_ESPACE
 */
int knot_response_add_rrset_additional(knot_packet_t *response,
                                       knot_rrset_t *rrset, uint32_t flags);

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
/*----------------------------------------------------------------------------*/
/*!
 * \brief Tries to compress domain name and creates its wire format.
 *
 * \param dname Domain name to convert and compress.
 * \param compr Compression table holding information about offsets of domain
 *              names in the packet.
 * \param dst Place where to put the wire format of the name.
 * \param max Maximum available size of the place for the wire format.
 *
 * \return Size of the domain name's wire format or KNOT_ESPACE if it did not
 *         fit into the provided space.
 */
int knot_response_compress_dname(const knot_dname_t *dname,
	knot_compr_t *compr, uint8_t *dst, size_t max);


#endif /* _KNOT_response_H_ */

/*! @} */
