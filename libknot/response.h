/*!
 * \file response.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Structure for holding response data and metadata.
 *
 * This structure can be used to pass all data needed for response creation
 * inside and between various processing functions of the application.
 *
 * \addtogroup libknot
 * @{
 */

#ifndef _KNOT_RESPONSE_H_
#define _KNOT_RESPONSE_H_

#include <stdint.h>
#include <string.h>

#include "dname.h"
#include "rrset.h"
#include "edns.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for holding information needed for compressing domain names.
 *
 * It's a simple table of domain names and their offsets in wire format of the
 * packet.
 *
 * \todo Consider using some better lookup structure, such as skip-list.
 */
struct knot_compressed_dnames {
	const knot_dname_t **dnames;  /*!< Domain names present in packet. */
	size_t *offsets;          /*!< Offsets of domain names in the packet. */
	short count;              /*!< Count of items in the previous arrays. */
	short max;                /*!< Capacity of the structure (allocated). */
};

typedef struct knot_compressed_dnames knot_compressed_dnames_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing the DNS packet header.
 *
 * \note Currently @a ancount, @a nscount and @a arcount hold the number of
 *       RRSets of corresponding type in the response structure. Real RR
 *       counts are counted in knot_response_to_wire() on-the-fly.
 */
struct knot_header {
	uint16_t id;      /*!< ID stored in host byte order. */
	uint8_t flags1;   /*!< First octet of header flags. */
	uint8_t flags2;   /*!< Second octet of header flags. */
	uint16_t qdcount; /*!< Number of Question RRs, in host byte order. */
	uint16_t ancount; /*!< Number of Answer RRs, in host byte order. */
	uint16_t nscount; /*!< Number of Authority RRs, in host byte order. */
	uint16_t arcount; /*!< Number of Additional RRs, in host byte order. */
};

typedef struct knot_header knot_header_t;

/*!
 * \brief Structure representing one Question entry in the DNS packet.
 */
struct knot_question {
	knot_dname_t *qname;  /*!< Question domain name. */
	uint16_t qtype;         /*!< Question TYPE. */
	uint16_t qclass;        /*!< Question CLASS. */
};

typedef struct knot_question knot_question_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing a response to a DNS query.
 *
 * Holds all information needed while processing the response.
 *
 * \note QNAME, Answer, Authority and Additonal sections are by default put to
 *       preallocated space after the structure with default sizes. If the
 *       space is not enough, more space is allocated dynamically.
 */
struct knot_response {
	/*! \brief DNS header. IDs and flags are copied from query. */
	knot_header_t header;

	/*!
	 * \brief Question section. Copied from query.
	 *
	 * \note Only one Question is supported!
	 */
	knot_question_t question;

	uint8_t *owner_tmp;  /*!< Allocated space for RRSet owner wire format.*/

	const knot_rrset_t **answer;      /*!< Answer RRSets. */
	const knot_rrset_t **authority;   /*!< Authority RRSets. */
	const knot_rrset_t **additional;  /*!< Additional RRSets. */

	short an_rrsets;     /*!< Count of Answer RRSets in the response. */
	short ns_rrsets;     /*!< Count of Authority RRSets in the response. */
	short ar_rrsets;     /*!< Count of Additional RRSets in the response. */

	short max_an_rrsets; /*!< Allocated space for Answer RRsets. */
	short max_ns_rrsets; /*!< Allocated space for Authority RRsets. */
	short max_ar_rrsets; /*!< Allocated space for Additional RRsets. */

	knot_opt_rr_t edns_query;     /*!< EDNS data parsed from query. */
	knot_opt_rr_t edns_response;  /*!< EDNS data provided by the server.*/

	uint8_t *wireformat;  /*!< Wire format of the response. */
	size_t size;      /*!< Current wire size of the response. */
	size_t max_size;  /*!< Maximum allowed size of the response. */

	/*! \brief Information needed for compressing domain names in packet. */
	knot_compressed_dnames_t compression;

	const knot_rrset_t **tmp_rrsets; /*!< Synthetized RRSets. */
	short tmp_rrsets_count;  /*!< Count of synthetized RRSets. */
	short tmp_rrsets_max;    /*!< Allocated space for synthetized RRSets. */
};

typedef struct knot_response knot_response_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new empty response structure.
 *
 * \param opt_rr OPT RR of the nameserver to be used in the response.
 *
 * \return New empty response structure or NULL if an error occured.
 */
knot_response_t *knot_response_new_empty(const knot_opt_rr_t *opt_rr);

/*!
 * \brief Creates new empty response structure.
 *
 * \param max_wire_size Maximum size of the wire format of the response.
 *
 * \return New empty response structure or NULL if an error occured.
 */
knot_response_t *knot_response_new(size_t max_wire_size);

/*!
 * \brief Clears the response structure for reuse.
 *
 * After call to this function, the response will be in the same state as if
 * knot_response_new() was called. The maximum wire size is retained.
 *
 * \param response Response structure to clear.
 */
void knot_response_clear(knot_response_t *resp, int clear_question);

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
int knot_response_add_opt(knot_response_t *resp,
                            const knot_opt_rr_t *opt_rr,
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
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 * \retval KNOT_ENOMEM
 *
 * \todo Needs test.
 */
int knot_response_set_max_size(knot_response_t *resp, int max_size);

/*!
 * \brief Parses the given query and saves important information into the
 *        response structure.
 *
 * Copies ID and flags from the header, parses first Question entry and EDNS
 * OPT RR.
 *
 * \param response Response to store the parsed information into.
 * \param query_wire Query in wire format.
 * \param query_size Size of the query in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EMALF
 * \retval KNOT_EFEWDATA
 * \retval KNOT_ENOMEM
 */
int knot_response_parse_query(knot_response_t *response,
                                const uint8_t *query_wire, size_t query_size);

/*!
 * \brief Returns the OPCODE of the query.
 *
 * \param response Response (with parsed query) to get the OPCODE from.
 *
 * \return OPCODE stored in the response.
 */
uint8_t knot_response_opcode(const knot_response_t *response);

/*!
 * \brief Returns the QNAME from the response.
 *
 * \param response Response (with parsed query) to get the QNAME from.
 *
 * \return QNAME stored in the response.
 */
const knot_dname_t *knot_response_qname(const knot_response_t *response);

/*!
 * \brief Returns the QTYPE from the response.
 *
 * \param response Responsee (with parsed query) to get the QTYPE from.
 *
 * \return QTYPE stored in the response.
 */
uint16_t knot_response_qtype(const knot_response_t *response);

/*!
 * \brief Returns the QCLASS from the response.
 *
 * \param response Response (with parsed query) to get the QCLASS from.
 *
 * \return QCLASS stored in the response.
 */
uint16_t knot_response_qclass(const knot_response_t *response);

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
int knot_response_add_rrset_answer(knot_response_t *response,
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
int knot_response_add_rrset_authority(knot_response_t *response,
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
int knot_response_add_rrset_additional(knot_response_t *response,
                                         const knot_rrset_t *rrset, int tc,
                                         int check_duplicates, int compr_cs);

/*!
 * \brief Sets the RCODE of the response.
 *
 * \param response Response to set the RCODE in.
 * \param rcode RCODE to set.
 */
void knot_response_set_rcode(knot_response_t *response, short rcode);

/*!
 * \brief Sets the AA bit of the response to 1.
 *
 * \param response Response in which the AA bit should be set.
 */
void knot_response_set_aa(knot_response_t *response);

/*!
 * \brief Sets the TC bit of the response to 1.
 *
 * \param response Response in which the TC bit should be set.
 */
void knot_response_set_tc(knot_response_t *response);

/*!
 * \brief Adds RRSet to the list of temporary RRSets.
 *
 * Temporary RRSets are fully freed when the response structure is destroyed.
 *
 * \param response Response to which the temporary RRSet should be added.
 * \param tmp_rrset Temporary RRSet to be stored in the response.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
int knot_response_add_tmp_rrset(knot_response_t *response,
                                  knot_rrset_t *tmp_rrset);

/*!
 * \brief Returns number of RRSets in Answer section of the response.
 *
 * \param response Response to get the Answer RRSet count from.
 */
short knot_response_answer_rrset_count(const knot_response_t *response);

/*!
 * \brief Returns number of RRSets in Authority section of the response.
 *
 * \param response Response to get the Authority RRSet count from.
 */
short knot_response_authority_rrset_count(const knot_response_t *response);

/*!
 * \brief Returns number of RRSets in Additional section of the response.
 *
 * \param response Response to get the Additional RRSet count from.
 */
short knot_response_additional_rrset_count(const knot_response_t *response);

/*!
 * \brief Returns the requested Answer RRset.
 *
 * \param response Response to get the RRSet from.
 * \param pos Position of the RRSet in the Answer section (RRSets are stored
 *            in the order they were added to the response).
 *
 * \return The RRSet on position \a pos in the Answer section of \a response
 *         or NULL if there is no such RRSet.
 */
const knot_rrset_t *knot_response_answer_rrset(
	const knot_response_t *response, short pos);

/*!
 * \brief Returns the requested Authority RRset.
 *
 * \param response Response to get the RRSet from.
 * \param pos Position of the RRSet in the Authority section (RRSets are stored
 *            in the order they were added to the response).
 *
 * \return The RRSet on position \a pos in the Authority section of \a response
 *         or NULL if there is no such RRSet.
 */
const knot_rrset_t *knot_response_authority_rrset(
	knot_response_t *response, short pos);

/*!
 * \brief Returns the requested Additional RRset.
 *
 * \param response Response to get the RRSet from.
 * \param pos Position of the RRSet in the Additional section (RRSets are stored
 *            in the order they were added to the response).
 *
 * \return The RRSet on position \a pos in the Additional section of \a response
 *         or NULL if there is no such RRSet.
 */
const knot_rrset_t *knot_response_additional_rrset(
	knot_response_t *response, short pos);

/*!
 * \brief Checks if DNSSEC was requested in the query (i.e. the DO bit was set).
 *
 * \param response Response where the parsed query is stored.
 *
 * \retval 0 if the DO bit was not set in the query, or the query is not yet
 *         parsed.
 * \retval > 0 if DO bit was set in the query.
 */
int knot_response_dnssec_requested(const knot_response_t *response);

/*!
 * \brief Checks if NSID was requested in the query (i.e. the NSID option was
 *        present in the query OPT RR).
 *
 * \param response Response where the parsed query is stored.
 *
 * \retval 0 if the NSID option was not present in the query, or the query is
 *         not yet parsed.
 * \retval > 0 if the NSID option was present in the query.
 */
int knot_response_nsid_requested(const knot_response_t *response);

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
int knot_response_add_nsid(knot_response_t *response, const uint8_t *data,
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
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 */
int knot_response_to_wire(knot_response_t *response,
                            uint8_t **resp_wire, size_t *resp_size);

/*!
 * \brief Properly destroys the response structure.
 *
 * \param response Response to be destroyed.
 */
void knot_response_free(knot_response_t **response);

/*!
 * \brief Dumps the whole response in human-readable form.
 *
 * \note This function is empty unless KNOT_RESPONSE_DEBUG is defined.
 *
 * \param resp Response to dump.
 */
void knot_response_dump(const knot_response_t *resp);

#endif /* _KNOT_RESPONSE_H_ */

/*! @} */
