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
 * \addtogroup dnslib
 * @{
 */
#ifndef _CUTEDNS_DNSLIB_RESPONSE_H_
#define _CUTEDNS_DNSLIB_RESPONSE_H_

#include <stdint.h>
#include <string.h>

#include "dname.h"
#include "rrset.h"

/*!
 * \brief Default maximum DNS response size
 *
 * This size must be supported by all servers and clients.
 */
static const short DNSLIB_MAX_RESPONSE_SIZE = 512;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for holding EDNS parameters.
 *
 * \todo NSID
 */
struct dnslib_edns_data {
	uint16_t payload;    /*!< UDP payload. */
	uint16_t ext_rcode;  /*!< Extended RCODE. */

	/*!
	 * \brief Supported version of EDNS.
	 *
	 * Set to EDNS_NOT_SUPPORTED if not supported.
	 */
	uint16_t version;
};

typedef struct dnslib_edns_data dnslib_edns_data_t;

static const uint16_t EDNS_NOT_SUPPORTED = 65535;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for holding information needed for compressing domain names.
 *
 * It's a simple table of domain names and their offsets in wire format of the
 * packet.
 *
 * \todo Consider using some better lookup structure, such as skip-list.
 */
struct dnslib_compressed_dnames {
	dnslib_dname_t **dnames;  /*!< Domain names present in packet. */
	short *offsets;           /*!< Offsets of domain names in the packet. */
	short count;              /*!< Count of items in the previous arrays. */
	short max;                /*!< Capacity of the structure (allocated). */
};

typedef struct dnslib_compressed_dnames dnslib_compressed_dnames_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure representing the DNS packet header.
 */
struct dnslib_header {
	uint16_t id;      /*!< ID stored in host byte order. */
	uint8_t flags1;   /*!< First octet of header flags. */
	uint8_t flags2;   /*!< Second octet of header flags. */
	uint16_t qdcount; /*!< Number of Question RRs, in host byte order. */
	uint16_t ancount; /*!< Number of Answer RRs, in host byte order. */
	uint16_t nscount; /*!< Number of Authority RRs, in host byte order. */
	uint16_t arcount; /*!< Number of Additional RRs, in host byte order. */
};

typedef struct dnslib_header dnslib_header_t;

/*!
 * \brief Structure representing one Question entry in the DNS packet.
 */
struct dnslib_question {
	dnslib_dname_t *qname;  /*!< Question domain name. */
	uint16_t qtype;         /*!< Question TYPE. */
	uint16_t qclass;        /*!< Question CLASS. */
};

typedef struct dnslib_question dnslib_question_t;

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
struct dnslib_response {
	/*! \brief DNS header. IDs and flags are copied from query. */
	dnslib_header_t header;

	/*!
	 * \brief Question section. Copied from query.
	 *
	 * \note Only one Question is supported!
	 */
	dnslib_question_t question;

	const dnslib_rrset_t **answer;      /*!< Answer RRSets. */
	const dnslib_rrset_t **authority;   /*!< Authority RRSets. */
	const dnslib_rrset_t **additional;  /*!< Additional RRSets. */

	short max_ancount; /*!< Allocated space for Answer RRsets. */
	short max_nscount; /*!< Allocated space for Authority RRsets. */
	short max_arcount; /*!< Allocated space for Additional RRsets. */

	/*!
	 * \brief EDNS data parsed from query.
	 *
	 * \todo Do we need this actually??
	 */
	dnslib_edns_data_t edns_query;

	/*!
	 * \brief EDNS OPT RR provided by the server.
	 *
	 * This is stored in wire format, as it may be prepared by the server
	 * in advance and only passed on response creation, there is no need to
	 * convert it each time.
	 *
	 * The necessary parsing which is done when creating the response is
	 * much faster than converting some structure to wire format.
	 */
	const uint8_t *edns_wire;
	short edns_size;  /*!< Size of the server EDNS OPT RR in bytes. */

	short size;      /*!< Current wire size of the response. */
	short max_size;  /*!< Maximum allowed size of the response. */

	/*! \brief Information needed for compressing domain names in packet. */
	dnslib_compressed_dnames_t compression;

	const dnslib_rrset_t **tmp_rrsets; /*!< Synthetized RRSets. */
	short tmp_rrsets_count;  /*!< Count of synthetized RRSets. */
	short tmp_rrsets_max;    /*!< Allocated space for synthetized RRSets. */
};

typedef struct dnslib_response dnslib_response_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new empty response structure.
 *
 * \note Does not copy the given EDNS wire data, only stores reference to it.
 *
 * \param edns_wire Wire format of the EDNS OPT pseudo-RR specifying EDNS
 *                  parameters of the host who creates the response.
 * \param edns_size Size of \a edns_wire in bytes.
 *
 * \return New empty response structure or NULL if an error occured.
 */
dnslib_response_t *dnslib_response_new_empty(const uint8_t *edns_wire,
                                             short edns_size);

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
 * \retval 0 if successful.
 * \retval <> 0 if an error occured.
 */
int dnslib_response_parse_query(dnslib_response_t *response,
                                const uint8_t *query_wire, size_t query_size);

/*!
 * \brief Adds a RRSet to the Answer section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 *
 * \retval 0 if successful.
 * \retval <> 0 if an error occured.
 */
int dnslib_response_add_rrset_answer(dnslib_response_t *response,
                                     const dnslib_rrset_t *rrset, int tc);

/*!
 * \brief Adds a RRSet to the Authority section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 *
 * \retval 0 if successful.
 * \retval <> 0 if an error occured.
 */
int dnslib_response_add_rrset_authority(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc);

/*!
 * \brief Adds a RRSet to the Additional section of the response.
 *
 * \param response Response to add the RRSet into.
 * \param rrset RRSet to be added.
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 *
 * \retval 0 if successful.
 * \retval <> 0 if an error occured.
 */
int dnslib_response_add_rrset_additional(dnslib_response_t *response,
                                         const dnslib_rrset_t *rrset, int tc);

/*!
 * \brief Sets the RCODE of the response.
 *
 * \param response Response to set the RCODE in.
 * \param rcode RCODE to set.
 */
void dnslib_response_set_rcode(dnslib_response_t *response, short rcode);

/*!
 * \brief Sets the AA bit of the response to 1.
 *
 * \param response Response in which the AA bit should be set.
 */
void dnslib_response_set_aa(dnslib_response_t *response);


int dnslib_response_add_tmp_rrset(dnslib_response_t *response,
                                  dnslib_rrset_t *tmp_rrset);

/*!
 * \brief Converts the response to wire format.
 *
 * \param response Response to be converted to wire format.
 * \param resp_wire Here the wire format of the response will be stored.
 *                  Space for the response will be allocated. *resp_wire must
 *                  be set to NULL (to avoid leaks).
 * \param resp_size Size of the response in wire format.
 *
 * \retval 0 if successful.
 * \retval -2 if \a *resp_wire was not set to NULL.
 */
int dnslib_response_to_wire(dnslib_response_t *response,
                            uint8_t **resp_wire, size_t *resp_size);

/*!
 * \brief Properly destroys the response structure.
 *
 * \param response Response to be destroyed.
 */
void dnslib_response_free(dnslib_response_t **response);

void dnslib_response_dump(const dnslib_response_t *resp);

#endif /* _CUTEDNS_DNSLIB_RESPONSE_H_ */

/*! @} */
