/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Dnstap file writer.
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
