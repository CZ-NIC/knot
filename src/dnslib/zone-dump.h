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

#ifndef _KNOTDKNOT_ZONEDUMP_H_
#define _KNOTDKNOT_ZONEDUMP_H_

#include "dnslib/zone.h"

/*!
 * \brief Zone loader enums.
 */
enum {
	MAGIC_LENGTH = 7 /*!< Compiled zone magic length. */
};

/*! \brief Magic identifier: { "knot", maj_ver, min_ver, revision } */
#define MAGIC_BYTES {'k', 'n', 'o', 't', '0', '2', 'a'}

/*!
 * \brief Dumps given zone to binary file.
 *
 * \param zone Zone to be saved.
 * \param filename Name of file to be created.
 * \param do_checks Set to 1 to enable checking the zone for semantic errors.
 * \param sfilename Source filename of the text zone file.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBADARG if the file cannot be opened for writing.
 */
int knot_zdump_binary(knot_zone_contents_t *zone, const char *filename,
                        int do_checks, const char *sfilename);

/*!
 * \brief Serializes RRSet into binary stream. Expects NULL pointer, memory
 *        is handled inside function.
 *
 * \param rrset RRSet to be serialized.
 * \param stream Stream containing serialized RRSet.
 * \param size Length of created stream.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBADARG if wrong arguments are supplied.
 * \retval KNOT_ENOMEM on memory error.
 */
int knot_zdump_rrset_serialize(const knot_rrset_t *rrset, uint8_t **stream,
                                 size_t *size);

/*!
 * \brief Serializes RRSet into binary stream. Expects NULL pointer, memory
 *        is handled inside function.
 *
 * \param rrset RRSet to be serialized.
 * \param stream Stream containing serialized RRSet.
 * \param size Length of created stream.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EBADARG if wrong arguments are supplied.
 * \retval KNOT_ENOMEM on memory error.
 */
int knot_zdump_rrset_serialize(const knot_rrset_t *rrset, uint8_t **stream,
                                 size_t *size);

#endif /* _KNOT_ZONEDUMP_H_ */

/*! @} */
