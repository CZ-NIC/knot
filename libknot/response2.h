/*!
 * \file response2.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief API for response manipulation.
 *
 * \addtogroup libknot
 * @{
 */

#ifndef _KNOT_RESPONSE2_H_
#define _KNOT_RESPONSE2_H_

#include <stdint.h>
#include <string.h>

#include "packet.h"

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
int knot_response2_init(knot_packet_t *response);

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
int knot_response2_init_from_query(knot_packet_t *response,
                                    knot_packet_t *query);

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
void knot_response2_clear(knot_packet_t *resp, int clear_question);

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
 * \retval KNOT_EBADARG
 * \retval KNOT_ENOMEM
 *
 * \todo Needs test.
 */
int knot_response2_add_opt(knot_packet_t *resp,
                            const knot_opt_rr_t *opt_rr,
                            int override_max_size);

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
int knot_response2_add_rrset_answer(knot_packet_t *response,
                                     const knot_rrset_t *rrset, int tc,
                                     int check_duplicates, int compr_cs);

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
int knot_response2_add_rrset_authority(knot_packet_t *response,
                                        const knot_rrset_t *rrset, int tc,
                                        int check_duplicates, int compr_cs);

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
int knot_response2_add_rrset_additional(knot_packet_t *response,
                                         const knot_rrset_t *rrset, int tc,
                                         int check_duplicates, int compr_cs);

/*!
 * \brief Sets the RCODE of the response.
 *
 * \param response Response to set the RCODE in.
 * \param rcode RCODE to set.
 */
void knot_response2_set_rcode(knot_packet_t *response, short rcode);

/*!
 * \brief Sets the AA bit of the response to 1.
 *
 * \param response Response in which the AA bit should be set.
 */
void knot_response2_set_aa(knot_packet_t *response);

/*!
 * \brief Sets the TC bit of the response to 1.
 *
 * \param response Response in which the TC bit should be set.
 */
void knot_response2_set_tc(knot_packet_t *response);

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
int knot_response2_add_nsid(knot_packet_t *response, const uint8_t *data,
                             uint16_t length);

#endif /* _KNOT_RESPONSE2_H_ */

/*! @} */
