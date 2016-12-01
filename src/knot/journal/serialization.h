/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*!
 * \brief Returns size of changeset in serialized form.
 *
 * \param[in] ch  Changeset whose size we want to compute.
 *
 * \return Size of the changeset.
 */
size_t changeset_serialized_size(const changeset_t *ch);

/*!
 * \brief Serializes one changeset into byte stream.
 *
 * \param[in]  ch    Changeset to serialize.
 * \param[out] dst   Output stream.
 * \param[in]  size  Output stream size.
 *
 * \return KNOT_E*
 */
int changeset_serialize(const changeset_t *ch, uint8_t *dst, size_t size);

/*!
 * \brief Deserializes one changeset from byte stream.
 *
 * \param[out] ch   Changeset to deserialize.
 * \param[in] src   Input stream.
 * \param[in] size  Input stream size.
 *
 * \return KNOT_E*
 */
int changeset_deserialize(changeset_t *ch, const uint8_t *src, size_t size);

/*!
 * \brief Serializes given changeset into chunked area.
 *
 * \param[in]  ch                The changeset
 * \param[in]  dst_chunks        The chunks to serialize into
 * \param[in]  chunk_size        Maximum size of each chunk
 * \param[in]  chunks_count      Maximum number of used chunks
 * \param[out] chunks_real_sizes real size of each chunk after serialization, or zeros for unused chunks
 * \param[out] chunks_real_count real # of chunks after serialization. Can be wrong if error returned!
 *
 * \retval KNOT_E*
 */
int changeset_serialize_chunks(const changeset_t *ch, uint8_t *dst_chunks[], size_t chunk_size, int chunks_count, size_t *chunks_real_sizes, int *chunks_real_count);

/*!
 * \brief Deserializes chunked area into ch
 *
 * \param[out] ch                The changeset
 * \param[in]  src_chunks        The chunks to deserialize
 * \param[in]  chunk_sizes       The size of each chunk
 * \param[in]  chunks_count      The number of chunks
 *
 * \retval KNOT_E*
 */
int changeset_deserialize_chunks(changeset_t *ch, uint8_t *src_chunks[], const size_t *chunks_sizes, int chunks_count);

/*! @} */
