/*!
 * \file zone-dump-text.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Functions for dumping zone to text file.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_ZONE_DUMP_TEXT_H_
#define _KNOT_DNSLIB_ZONE_DUMP_TEXT_H_

#include "dnslib/descriptor.h"
#include "dnslib/zone.h"

/*!
 * \brief Dumps given zone to text (BIND-like) file.
 *
 * \param zone Zone to be saved.
 * \param filename Name of file to be created.
 *
 * \retval DNSLIB_EOK on success.
 * \retval DNSLIB_EBADARG if the specified file is not valid for writing.
 */
int zone_dump_text(dnslib_zone_contents_t *zone, const char *filename);

#endif // _KNOT_DNSLIB_ZONE_DUMP_TEXT_H_

/*! @} */
