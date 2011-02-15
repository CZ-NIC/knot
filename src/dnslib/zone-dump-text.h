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

#include "descriptor.h"
#include "zone.h"

/*!
 * \brief Dumps given zone to text (BIND-like) file.
 *
 * \param zone Zone to be saved.
 * \param filename Name of file to be created.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int zone_dump_text(dnslib_zone_t *zone, const char *filename);
