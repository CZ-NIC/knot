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

#include <stdio.h>

#include "dnslib/zone.h"

/*!
 * \brief Zone loader structure.
 */
typedef struct zloader_t
{
	char *filename;           /*!< Compiled zone filename. */
	char *source;             /*!< Zone source file. */
	FILE *fp;                 /*!< Open filepointer to compiled zone. */

} zloader_t;

/*!
 * \brief Initializes zone loader from file..
 *
 * \param filename File containing the compiled zone.
 *
 * \retval Initialized loader on success.
 * \retval NULL on error.
 */
zloader_t *dnslib_zload_open(const char *filename);

/*!
 * \brief Loads zone from a compiled and serialized zone file.
 *
 * \param loader Zone loader instance.
 *
 * \retval Loaded zone on success.
 * \retval NULL otherwise.
 */
dnslib_zone_t *dnslib_zload_load(zloader_t *loader);

/*!
 * \brief Checks whether the compiled zone needs a recompilation.
 *
 * \param loader Zone loader instance.
 *
 * \retval True is if needs to be recompiled.
 * \retval False if it is up to date.
 */
int dnslib_zload_needs_update(zloader_t *loader);


/*!
 * \brief Free zone loader.
 *
 * \param loader Zone loader instance.
 */
void dnslib_zload_close(zloader_t *loader);

#endif /* _KNOT_ZONELOAD_H_ */

/*! @} */
