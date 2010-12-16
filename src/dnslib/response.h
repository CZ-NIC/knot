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

/*----------------------------------------------------------------------------*/
/*!
 * MTU <= 4500B
 * IP header has 24 B
 * DNS header has 12 B
 * DNS question is at least 5 B long (2 bytes TYPE, 2 bytes CLASS, 1 byte QNAME)
 * Each DNS RR is at least 11 B long:
 *   TYPE: 2 B
 *   CLASS: 2 B
 *   TTL: 4 B
 *   RDLENGTH: 2 B
 *   OWNER: at least 1 B (root label)
 *   RDATA: may be 0 B (theoretically)
 *
 * (4500 - 24 - 12 - 5) / 11 = 405
 */
static const size_t MAX_RRS_IN_RESPONSE = 405;

/*----------------------------------------------------------------------------*/
/*!
 * \todo NSID
 */
struct dnslib_edns_data {
	uint16_t payload;
	uint16_t ext_rcode;
	uint16_t version;
};

typedef struct dnslib_edns_data dnslib_edns_data_t;

/*----------------------------------------------------------------------------*/
/*!
 *
 */
struct dnslib_compressed_dnames {
	dnslib_dname_t *dnames;
	size_t *offsets;
	short count;
	short max;
};

typedef struct dnslib_compressed_dnames dnslib_compressed_dnames_t;

/*----------------------------------------------------------------------------*/
/*!
 *
 */
struct dnslib_header {
	uint8_t id[2];    /*!< ID stored in network byte order. */
	uint8_t flags1;   /*!< First octet of header flags. */
	uint8_t flags2;   /*!< Second octet of header flags. */
	uint16_t qdcount; /*!< Number of Question RRs, in host byte order. */
	uint16_t ancount; /*!< Number of Answer RRs, in host byte order. */
	uint16_t nscount; /*!< Number of Authority RRs, in host byte order. */
	uint16_t arcount; /*!< Number of Additional RRs, in host byte order. */
};

typedef struct dnslib_header dnslib_header_t;

struct dnslib_question {
	dnslib_dname_t *qname;
	uint16_t qtype;
	uint16_t qclass;
};

typedef struct dnslib_question dnslib_question_t;

/*----------------------------------------------------------------------------*/
/*!
 * \note QNAME, Answer, Authority and Additonal sections are by default put to
 *       preallocated space after the structure with default sizes. If the
 *       space is not enough, more space is allocated dynamically.
 */
struct dnslib_response {
	/*!
	 * \note Only one Question is supported!
	 */
	dnslib_question_t question;

	short max_size;  /*!< Maximum allowed size of the response. */

	dnslib_rrset_t *answer;
	dnslib_rrset_t *authority;
	dnslib_rrset_t *additional;

	short max_ancount; /*!< Allocated space for Answer RRsets. */
	short max_nscount; /*!< Allocated space for Authority RRsets. */
	short max_arcount; /*!< Allocated space for Additional RRsets. */

	dnslib_header_t header;

	/*!
	 * \brief EDNS data parsed from query.
	 *
	 * \todo Do we need this actually??
	 */
	dnslib_edns_data_t edns_query;
	const uint8_t *edns_wire;
	short edns_size;

	dnslib_compressed_dnames_t compression;

	dnslib_dname_t **tmp_dnames; /*!< Synthetized domain names. */
	short tmp_dname_count;   /*!< Count of synthetized domain names. */
	short tmp_dname_max;     /*!< Allocated space for synthetized dnames. */
};

typedef struct dnslib_response dnslib_response_t;

/*----------------------------------------------------------------------------*/

dnslib_response_t *dnslib_response_new_empty(const uint8_t *edns_wire,
                                             short edns_size);

int dnslib_response_parse_query(dnslib_response_t *response,
                                const uint8_t *query_wire, size_t query_size);

/*!
 * \param tc Set to <> 0 if omitting this RRSet should result in the TC bit set.
 *           Otherwise set to 0.
 */
int dnslib_response_add_rrset_answer(dnslib_response_t *response,
                                     const dnslib_rrset_t *rrset, int tc);

int dnslib_response_add_rrset_authority(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc);

int dnslib_response_add_rrset_aditional(dnslib_response_t *response,
                                        const dnslib_rrset_t *rrset, int tc);

/*
 * TODO: some functions for setting RCODE and flags!
 */

int dnslib_response_to_wire(dnslib_response_t *response,
                            uint8_t **resp_wire, size_t *resp_size);

void dnslib_response_free(dnslib_response_t **response);

#endif /* _CUTEDNS_DNSLIB_RESPONSE_H_ */

/*! @} */
