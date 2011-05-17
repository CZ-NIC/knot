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

/*!
 * \brief Checks if a zone transfer is required by comparing the zone's SOA with
 *        the one received from master server.
 *
 * \param zone Zone to check.
 * \param soa_response Response to SOA query received from master server.
 *
 * \retval < 0 if an error occured.
 * \retval 1 if the transfer is needed.
 * \retval 0 if the transfer is not needed.
 */
int axfrin_transfer_needed(const dnslib_zone_t *zone,
                           dnslib_packet_t *soa_response);


int axfrin_create_axfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                             size_t *size);

#endif /* _KNOT_AXFR_IN_H_ */

/*! @} */
