/*!
 * \file rrset.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Loader of previously parsed zone
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_ZONELOAD_H_
#define _CUTEDNS_ZONELOAD_H_

#include "dnslib/zone.h"

/*!
 * \brief Loades a zone from dump created by zone compiler.
 *
 * \param filename File containing the dumped zone.
 *
 * \param origin Zone's origin.
 *
 * \return Loaded zone on success, NULL otherwise.
 */
dnslib_zone_t *dnslib_zone_load(const char *filename, const char *origin);

#endif /* _CUTEDNS_ZONELOAD_H_ */

