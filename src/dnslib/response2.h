/*!
 * \file response2.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief API for response manipulation.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_RESPONSE2_H_
#define _KNOT_DNSLIB_RESPONSE2_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/packet.h"

#include "dnslib/dname.h"
#include "dnslib/rrset.h"
#include "dnslib/edns.h"

/*!
 * \brief Default maximum DNS response size
 *
 * This size must be supported by all servers and clients.
 */
static const short DNSLIB_MAX_RESPONSE_SIZE = 512;

/*----------------------------------------------------------------------------*/
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
 * \retval DNSLIB_EOK
 */
int dnslib_response2_init_from_query(dnslib_packet_t *response,
                                    dnslib_packet_t *query);

/*!
 * \brief Clears the response structure for reuse.
 *
 * After call to this function, the response will be in the same state as if
 * dnslib_response_new() was called. The maximum wire size is retained.
 *
 * \param response Response structure to clear.
 *
 * \todo Replace the use of this function with something else maybe?
 */
void dnslib_response2_clear(dnslib_packet_t *resp, int clear_question);

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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 *
 * \todo Needs test.
 */
int dnslib_response2_add_opt(dnslib_packet_t *resp,
                            const dnslib_opt_rr_t *opt_rr,
                            int override_max_size);

/*!
 * \brief Sets the maximum size of the response and allocates space for wire
 *        format (if needed).
 *
 * This function also allocates space for the wireformat of the response, if
 * the given max size is larger than the current maximum size of the response
 * and copies the current wireformat over to the new space.
 *
 * \warning Do not call this function if you are not completely sure that the
 *          current wire format of the response fits into the new space.
 *          It does not update the current size of the wire format, so the
 *          produced response may be larger than the given max size.
 *
 * \param resp Response to set the maximum size of.
 * \param max_size Maximum size of the response.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 *
 * \todo Needs test.
 */
int dnslib_response2_set_max_size(dnslib_packet_t *resp, int max_size);

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
 * \retval DNSLIB_EOK if successful, or the RRSet was already in the answer.
 * \retval DNSLIB_ENOMEM
 * \retval DNSLIB_ESPACE
 */
int dnslib_response2_add_rrset_answer(dnslib_packet_t *response,
                                     const dnslib_rrset_t *rrset, int tc,
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
 * \retval DNSLIB_EOK if successful, or the RRSet was already in the answer.
 * \retval DNSLIB_ENOMEM
 * \retval DNSLIB_ESPACE
 */
int dnslib_response2_add_rrset_authority(dnslib_packet_t *response,
                                        const dnslib_rrset_t *rrset, int tc,
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
 * \retval DNSLIB_EOK if successful, or the RRSet was already in the answer.
 * \retval DNSLIB_ENOMEM
 * \retval DNSLIB_ESPACE
 */
int dnslib_response2_add_rrset_additional(dnslib_packet_t *response,
                                         const dnslib_rrset_t *rrset, int tc,
                                         int check_duplicates, int compr_cs);

/*!
 * \brief Sets the RCODE of the response.
 *
 * \param response Response to set the RCODE in.
 * \param rcode RCODE to set.
 */
void dnslib_response2_set_rcode(dnslib_packet_t *response, short rcode);

/*!
 * \brief Sets the AA bit of the response to 1.
 *
 * \param response Response in which the AA bit should be set.
 */
void dnslib_response2_set_aa(dnslib_packet_t *response);

/*!
 * \brief Sets the TC bit of the response to 1.
 *
 * \param response Response in which the TC bit should be set.
 */
void dnslib_response2_set_tc(dnslib_packet_t *response);

/*!
 * \brief Adds NSID option to the response.
 *
 * \param response Response to add the NSID option into.
 * \param data NSID data.
 * \param length Size of NSID data in bytes.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOMEM
 */
int dnslib_response2_add_nsid(dnslib_packet_t *response, const uint8_t *data,
                             uint16_t length);

/*!
 * \brief Converts the response to wire format.
 *
 * \param response Response to be converted to wire format.
 * \param resp_wire Here the wire format of the response will be stored.
 *                  Space for the response will be allocated. *resp_wire must
 *                  be set to NULL (to avoid leaks).
 * \param resp_size The size of the response in wire format will be stored here.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 */
int dnslib_response2_to_wire(dnslib_packet_t *response,
                             uint8_t **resp_wire, size_t *resp_size);

#endif /* _KNOT_DNSLIB_RESPONSE2_H_ */

/*! @} */
