/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
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

#ifndef _KNOT_ZONEDUMP_H_
#define _KNOT_ZONEDUMP_H_

#include "common/crc.h"
#include "libknot/zone/zone.h"

/*!
 * \brief Zone loader enums.
 */
enum {
	MAGIC_LENGTH = 7 /*!< Compiled zone magic length. */
};

/*! \brief Magic identifier: { "knot", maj_ver, min_ver, revision } */
#define MAGIC_BYTES {'k', 'n', 'o', 't', '0', '8', '0'}

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

int knot_zdump_dump_and_swap(knot_zone_contents_t *zone,
                             const char *temp_zonedb,
                             const char *destination_zonedb,
                             const char *sfilename);

#endif /* _KNOT_ZONEDUMP_H_ */

/*! @} */
