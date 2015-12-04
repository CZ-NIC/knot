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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 *
 * \author Robert Edmonds <edmonds@fsi.io>
 *
 * \brief Dnstap file writer.
 *
 * \addtogroup dnstap
 * @{
 */

#pragma once

#include <fstrm.h>
#include <protobuf-c/protobuf-c.h>

/*! \brief Structure for dnstap file writer. */
typedef struct {
	/*!< Output writer. */
	struct fstrm_writer	*fw;

	/*!< dnstap "version" field. */
	void			*version;

	/*!< length of dnstap "version" field. */
	size_t			len_version;
} dt_writer_t;

/*!
 * \brief Creates dnstap file writer structure.
 *
 * \param file_path		Name of file to write output to.
 * \param version		Version string of software. May be NULL.
 *
 * \retval writer		if success.
 * \retval NULL			if error.
 */
dt_writer_t* dt_writer_create(const char *file_path, const char *version);

/*!
 * \brief Finish writing dnstap file writer and free resources.
 *
 * \param writer		dnstap file writer structure.
 */
void dt_writer_free(dt_writer_t *writer);

/*!
 * \brief Write a protobuf to the dnstap file writer.
 *
 * Supported protobuf types for the 'msg' parameter:
 *	\c Dnstap__Message
 *
 * \param writer		dnstap file writer structure.
 * \param msg			dnstap protobuf. Must be a supported type.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int dt_writer_write(dt_writer_t *writer, const ProtobufCMessage *msg);

/*! @} */
