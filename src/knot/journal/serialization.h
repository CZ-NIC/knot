/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>
#include "libknot/rrset.h"
#include "knot/updates/changesets.h"
#include "contrib/wire_ctx.h"

typedef struct serialize_ctx serialize_ctx_t;

/*!
 * \brief Init serialization context.
 *
 * \param ch  Changeset to be serialized.
 *
 * \return Context.
 */
serialize_ctx_t *serialize_init(const changeset_t *ch);

/*!
 * \brief Init serialization context.
 *
 * \param z   Zone to be serialized like zone-in-journal changeset.
 *
 * \return Context.
 */
serialize_ctx_t *serialize_zone_init(const zone_contents_t *z);

/*!
 * \brief Pre-check and space computation before serializing a chunk.
 *
 * \note This MUST be called before each serialize_chunk() !
 *
 * \param ctx      Serializing context.
 * \param max_size Maximum size of next chunk.
 * \param realsize Output: real exact size of next chunk.
 */
void serialize_prepare(serialize_ctx_t *ctx, size_t max_size, size_t *realsize);

/*!
 * \brief Perform one step of serializiation: fill one chunk.
 *
 * \param ctx        Serializing context.
 * \param chunk      Pointer on allocated memory to be serialized into.
 * \param chunk_size Its size. It MUST be the same as returned from serialize_prepare().
 */
void serialize_chunk(serialize_ctx_t *ctx, uint8_t *chunk, size_t chunk_size);

/*! \brief Tells if there remains something of the changeset
 *         to be serialized into next chunk(s) yet. */
bool serialize_unfinished(serialize_ctx_t *ctx);

/*! \brief Free serialization context. */
void serialize_deinit(serialize_ctx_t *ctx);

/*!
 * \brief Returns size of changeset in serialized form.
 *
 * \param[in] ch  Changeset whose size we want to compute.
 *
 * \return Size of the changeset.
 */
size_t changeset_serialized_size(const changeset_t *ch);

/*!
 * \brief Simply serialize RRset w/o any chunking.
 *
 * \param wire
 * \param rrset
 *
 * \return KNOT_E*
 */
int serialize_rrset(wire_ctx_t *wire, const knot_rrset_t *rrset);

/*!
 * \brief Simply deserialize RRset w/o any chunking.
 *
 * \param wire
 * \param rrset
 *
 * \return KNOT_E*
 */
int deserialize_rrset(wire_ctx_t *wire, knot_rrset_t *rrset);

/*!
 * \brief Space needed to serialize RRset.
 *
 * \param rrset RRset.
 *
 * \return RRset binary size.
 */
size_t rrset_serialized_size(const knot_rrset_t *rrset);
