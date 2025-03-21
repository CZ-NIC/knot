/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Dnstap file reader.
 */

#pragma once

#include <fstrm.h>
#include <protobuf-c/protobuf-c.h>

#include "contrib/dnstap/dnstap.pb-c.h"

/*! \brief Structure for dnstap file reader. */
typedef struct {
	/*!< Input reader. */
	struct fstrm_reader	*fr;
} dt_reader_t;

/*!
 * \brief Creates dnstap file reader structure.
 *
 * \param file_path		Name of file to read input from.
 *
 * \retval reader		if success.
 * \retval NULL			if error.
 */
dt_reader_t* dt_reader_create(const char *file_path);

/*!
 * \brief Close dnstap file reader.
 *
 * \param reader		dnstap file reader structure.
 */
void dt_reader_free(dt_reader_t *reader);

/*!
 * \brief Read a dnstap protobuf from a dnstap file reader.
 *
 * Caller must deallocate the returned protobuf with the
 * dnstap__dnstap__free_unpacked() function.
 *
 * \param[in]  reader		dnstap file reader structure.
 * \param[out] d     		Unpacked dnstap protobuf.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 * \retval KNOT_EOF
 * \retval KNOT_ENOMEM
 */
int dt_reader_read(dt_reader_t *reader, Dnstap__Dnstap **d);

/*!
 * \brief free the frame allocated by dt_read_data.
 *
 * \param reader                Dnstap reader context.
 * \param d                     The frame to be freed.
 */
void dt_reader_free_frame(dt_reader_t *reader, Dnstap__Dnstap **d);
