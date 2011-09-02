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

#ifndef _KNOT_ZONELOAD_H_
#define _KNOT_ZONELOAD_H_

#include <stdio.h>

#include "libknot/zone/zone.h"

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
 * \param loader Will create new loader in *loader.
 *
 * \retval Initialized loader on success.
 * \retval NULL on error.
 */
int knot_zload_open(zloader_t **loader, const char *filename);

/*!
 * \brief Loads zone from a compiled and serialized zone file.
 *
 * \param loader Zone loader instance.
 *
 * \retval Loaded zone on success.
 * \retval NULL otherwise.
 */
knot_zone_t *knot_zload_load(zloader_t *loader);

/*!
 * \brief Checks whether the compiled zone needs a recompilation.
 *
 * \param loader Zone loader instance.
 *
 * \retval 1 is if needs to be recompiled.
 * \retval 0 if it is up to date.
 */
int knot_zload_needs_update(zloader_t *loader);


/*!
 * \brief Free zone loader.
 *
 * \param loader Zone loader instance.
 */
void knot_zload_close(zloader_t *loader);

/*!
 * \brief Loads RRSet serialized by knot_zdump_rrset_serialize().
 *
 * \param stream Stream containing serialized RRSet.
 * \param size Size of stream. This variable will contain remaining length of
 *        stream, once the function has ended.
 * \param rrset Place for created RRSet.
 *
 * \note If RRSet contains RRSIGs, their owners are not copies, but only links
 *       to the owner of RRSet. All RDATA dnames are copied.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBADAG on wrong arguments.
 * \retval KNOT_EMALF when stream is malformed.
 */
int knot_zload_rrset_deserialize(knot_rrset_t **rrset,
                                   uint8_t *stream, size_t *size);

#endif /* _KNOTD_ZONELOAD_H_ */

/*! @} */
