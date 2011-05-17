/*!
 * \file notify.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief NOTIFY request/reply API.
 *
 * \addtogroup query_processing
 * @{
 */

#ifndef _KNOT_NOTIFY_H_
#define _KNOT_NOTIFY_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/zone.h"
#include "dnslib/packet.h"
#include "dnslib/zonedb.h"

int notify_create_request(const dnslib_zone_t *zone, uint8_t *buffer,
                          size_t *size);

int notify_process_request(dnslib_packet_t *notify,
                           const dnslib_zonedb_t *zonedb,
                           const dnslib_zone_t **zone,
                           uint8_t *buffer, size_t *size);

int notify_process_response(const dnslib_zone_t *zone, dnslib_packet_t *notify);

#endif /* _KNOT_NOTIFY_H_ */

/*! @} */
