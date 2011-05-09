/*!
 * \file axfr-in.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief AXFR client API.
 *
 * \addtogroup query_processing
 * @{
 */

#ifndef _KNOT_AXFR_IN_H_
#define _KNOT_AXFR_IN_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/dname.h"
#include "dnslib/zone.h"
#include "dnslib/packet.h"

int axfrin_create_soa_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size);

int axfrin_transfer_needed(const dnslib_zone_t *zone,
                           const dnslib_packet_t *soa_response);

int axfrin_create_axfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                             size_t *size);

#endif

/*! @} */
