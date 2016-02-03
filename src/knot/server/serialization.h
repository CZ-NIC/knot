/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief API for changeset serialization.
 *
 * \addtogroup server
 * @{
 */

#pragma once

#include <stdint.h>
#include "libknot/rrset.h"
#include "knot/updates/changesets.h"

/*!
 * \brief Returns size of changeset in serialized form.
 *
 * \param chgset  Changeset whose size we want to compute.
 * \param size    Output size parameter.
 *
 * \return KNOT_E*
 */
int changeset_binary_size(const changeset_t *chgset, size_t *size);

/*!
 * \brief Serializes one RRSet into given stream.
 *
 * \param rrset   RRSet to be serialized.
 * \param stream  Stream to store RRSet into.
 * \param size    Output size of serialized RRSet in the stream.
 *
 * \return KNOT_E*
 */
int rrset_serialize(const knot_rrset_t *rrset, uint8_t *stream, size_t *size);

/*!
 * \brief Deserializes RRSet from given stream.
 *
 * \param stream       Stream containing serialized RRSet.
 * \param stream_size  Output stream size after RRSet has been deserialized.
 * \param rrset        Output deserialized rrset.
 *
 * \return KNOT_E*
 */
int rrset_deserialize(const uint8_t *stream, size_t *stream_size,
                      knot_rrset_t *rrset);

/*! @} */
