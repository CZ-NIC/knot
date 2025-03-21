/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Public interface for dnstap.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "contrib/dnstap/dnstap.pb-c.h"

/*! \brief Frame Streams "Content Type" value for dnstap. */
#define DNSTAP_CONTENT_TYPE     "protobuf:dnstap.Dnstap"

/*!
 * \brief Serializes a filled out dnstap protobuf struct. Dynamically allocates
 * storage for the serialized frame.
 *
 * \note This function returns a copy of its parameter return value 'buf' to
 * make error checking slightly easier.
 *
 * \param d             dnstap protobuf struct.
 * \param[out] buf      Serialized frame.
 * \param[out] sz       Size in bytes of the serialized frame.
 *
 * \return              Serialized frame.
 * \retval NULL         if error.
 */
uint8_t* dt_pack(const Dnstap__Dnstap *d, uint8_t **buf, size_t *sz);
