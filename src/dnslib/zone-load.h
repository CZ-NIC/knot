/*!
 * \file zone-load.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Loader of previously parsed zone
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_ZONELOAD_H_
#define _KNOT_DNSLIB_ZONELOAD_H_

#include "dnslib/zone.h"

/*!
 * \brief Loades a zone from dump created by zone compiler.
 *
 * \param filename File containing the dumped zone.
 *
 * \return Loaded zone on success, NULL otherwise.
 */
dnslib_zone_t *dnslib_zload_load(const char *filename);

#endif /* _KNOT_ZONELOAD_H_ */

