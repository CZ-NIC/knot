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

#ifndef _KNOT_DNSLIB_EDNS_H_
#define _KNOT_DNSLIB_EDNS_H_

#include <stdint.h>

#include "dnslib/utils.h"

enum dnslib_edns_offsets {
	DNSLIB_EDNS_OFFSET_PAYLOAD = 3,
	DNSLIB_EDNS_OFFSET_EXT_RCODE = 5,
	DNSLIB_EDNS_OFFSET_VERSION = 6,
	DNSLIB_EDNS_OFFSET_RDLENGTH = 9,
	DNSLIB_EDNS_OFFSET_RDATA = 11
};

static inline uint16_t dnslib_edns_get_payload(const uint8_t *edns_wire)
{
	return dnslib_wire_read_u16(edns_wire + DNSLIB_EDNS_OFFSET_PAYLOAD);
}

static inline void dnslib_edns_set_payload(uint8_t *edns_wire,
                                               uint16_t payload)
{
	dnslib_wire_write_u16(edns_wire + DNSLIB_EDNS_OFFSET_PAYLOAD, payload);
}

static inline uint8_t dnslib_edns_get_ext_rcode(const uint8_t *edns_wire)
{
	return *(edns_wire + DNSLIB_EDNS_OFFSET_EXT_RCODE);
}

static inline void dnslib_edns_set_ext_rcode(uint8_t *edns_wire,
                                             uint8_t ext_rcode)
{
	*(edns_wire + DNSLIB_EDNS_OFFSET_EXT_RCODE) = ext_rcode;
}

static inline uint8_t dnslib_edns_get_version(const uint8_t *edns_wire)
{
	return *(edns_wire + DNSLIB_EDNS_OFFSET_VERSION);
}

static inline void dnslib_edns_set_version(uint8_t *edns_wire, uint8_t version)
{
	*(edns_wire + DNSLIB_EDNS_OFFSET_VERSION) = version;
}

#endif /* _KNOT_DNSLIB_EDNS_H_ */

/*! @} */
