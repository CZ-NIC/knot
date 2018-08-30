/*  Copyright (C) 2014 Farsight Security, Inc. <software@farsightsecurity.com>

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
/*!
 * \author Robert Edmonds <edmonds@fsi.io>
 *
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
