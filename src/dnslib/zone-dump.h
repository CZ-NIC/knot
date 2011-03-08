/*!
 * \file zone-dump.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Functions for dumping zone to binary file.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_ZONEDUMP_H_
#define _KNOT_DNSLIB_ZONEDUMP_H_

#include "dnslib/zone.h"

/*!
 * \brief Dumps given zone to binary file.
 *
 * \param zone Zone to be saved.
 * \param filename Name of file to be created.
 *
 * \retval 0 on success.
 * \retval 1 on error.
 */
int dnslib_zdump_binary(dnslib_zone_t *zone, const char *filename,
			char do_checks);

#endif /* _DNSLIB_ZONEDUMP_H_ */

