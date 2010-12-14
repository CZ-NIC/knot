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

/*!
 * \note Current size of the structure:
 *         32bit machine: 18 + 405 x 3 x 4 = 4878 B
 *         64bit machine: 34 + 405 x 3 x 8 = 9754 B
 *
 * \todo Consider dynamically resizing the arrays for RRSets. With well picked
 *       default sizes we could avoid much reallocations (or any at all) and
 *       keep the space reasonably small.
 * \todo Structures for compressing domain names.
 * \todo Structure for EDNS information parsed from the query.
 */
struct dnslib_response {
	/*!
	 * \brief Normalized QNAME.
	 *
	 * \note Only one Question is supported!
	 */
	dnslib_dname_t *qname;
	uint16_t qtype;

	size_t max_size;  /*!< Maximum allowed size of the response. */

	uint8_t *resp_wire;
	size_t resp_size;

	/*! \todo Consider using one array. It would save space but cause
	 *        more difficult converting to wire format.
	 */
	dnslib_rrset_t *answer[MAX_RRS_IN_RESPONSE];
	dnslib_rrset_t *authority[MAX_RRS_IN_RESPONSE];
	dnslib_rrset_t *additional[MAX_RRS_IN_RESPONSE];
};

typedef struct dnslib_response dnslib_response_t;

#endif /* _CUTEDNS_DNSLIB_RESPONSE_H_ */

/*! @} */
