/*!
 * \file edns.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Functions for manipulating and parsing EDNS OPT pseudo-RR.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_DNSLIB_EDNS_H_
#define _CUTEDNS_DNSLIB_EDNS_H_

#include <stdint.h>

#include "utils.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for holding EDNS parameters.
 *
 * \todo NSID
 */
struct dnslib_opt_rr {
	uint16_t payload;    /*!< UDP payload. */
	uint16_t ext_rcode;  /*!< Extended RCODE. */

	/*!
	 * \brief Supported version of EDNS.
	 *
	 * Set to EDNS_NOT_SUPPORTED if not supported.
	 */
	uint16_t version;

	uint8_t *wire;
	short size;
	short allocated;
};

typedef struct dnslib_opt_rr dnslib_opt_rr_t;

enum dnslib_edns_offsets {
	DNSLIB_EDNS_OFFSET_PAYLOAD = 3,
	DNSLIB_EDNS_OFFSET_EXT_RCODE = 5,
	DNSLIB_EDNS_OFFSET_VERSION = 6,
	DNSLIB_EDNS_OFFSET_RDLENGTH = 9,
	DNSLIB_EDNS_OFFSET_RDATA = 11
};

static const uint16_t EDNS_NOT_SUPPORTED = 65535;

/*----------------------------------------------------------------------------*/

dnslib_opt_rr_t *dnslib_edns_new();

uint16_t dnslib_edns_get_payload(const dnslib_opt_rr_t *opt_rr);

void dnslib_edns_set_payload(dnslib_opt_rr_t *opt_rr, uint16_t payload);

uint8_t dnslib_edns_get_ext_rcode(const dnslib_opt_rr_t *opt_rr);

void dnslib_edns_set_ext_rcode(dnslib_opt_rr_t *opt_rr, uint8_t ext_rcode);

uint8_t dnslib_edns_get_version(const dnslib_opt_rr_t *opt_rr);

void dnslib_edns_set_version(dnslib_opt_rr_t *opt_rr, uint8_t version);

const uint8_t *dnslib_edns_wire(dnslib_opt_rr_t *opt_rr);

short dnslib_edns_size(dnslib_opt_rr_t *opt_rr);

#endif /* _CUTEDNS_DNSLIB_EDNS_H_ */

/*! @} */
