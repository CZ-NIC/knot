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

#ifndef _KNOT_ZONE_DUMP_TEXT_H_
#define _KNOT_ZONE_DUMP_TEXT_H_

#include "libknot/util/descriptor.h"
#include "libknot/zone/zone.h"

/*!
 * \brief Dumps given zone to text (BIND-like) file.
 *
 * \param zone Zone to be saved.
 * \param filename Name of file to be created.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBADARG if the specified file is not valid for writing.
 */
int zone_dump_text(knot_zone_contents_t *zone, const char *filename);

#endif // _KNOT_ZONE_DUMP_TEXT_H_

/*! @} */
