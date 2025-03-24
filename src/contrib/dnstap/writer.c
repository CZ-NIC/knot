/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/errcode.h"

#include "contrib/dnstap/dnstap.h"
#include "contrib/dnstap/writer.h"

dt_writer_t* dt_writer_create(const char *file_path, const char *version)
{
	struct fstrm_file_options *fopt = NULL;
	struct fstrm_writer_options *wopt = NULL;
	dt_writer_t *writer = NULL;
	fstrm_res res;

	writer = calloc(1, sizeof(dt_writer_t));
	if (writer == NULL) {
		goto fail;
	}

	// Set "version".
	if (version != NULL) {
		writer->len_version = strlen(version);
		writer->version = strdup(version);
		if (!writer->version) {
			goto fail;
		}
	}

	// Open writer.
	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, file_path);
	wopt = fstrm_writer_options_init();
	fstrm_writer_options_add_content_type(wopt,
		(const uint8_t *) DNSTAP_CONTENT_TYPE,
		strlen(DNSTAP_CONTENT_TYPE));
	writer->fw = fstrm_file_writer_init(fopt, wopt);
	fstrm_file_options_destroy(&fopt);
	fstrm_writer_options_destroy(&wopt);
	if (writer->fw == NULL) {
		goto fail;
	}

	res = fstrm_writer_open(writer->fw);
	if (res != fstrm_res_success) {
		goto fail;
	}

	return writer;
fail:
	dt_writer_free(writer);
	return NULL;
}

void dt_writer_free(dt_writer_t *writer)
{
	if (writer == NULL) {
		return;
	}

	fstrm_writer_destroy(&writer->fw);
	free(writer->version);
	free(writer);
}

int dt_writer_write(dt_writer_t *writer, const ProtobufCMessage *msg)
{
	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;
	size_t len;
	uint8_t *data;

	if (writer->fw == NULL) {
		return KNOT_EOK;
	}

	// Only handle dnstap/Message.
	assert(msg->descriptor == &dnstap__message__descriptor);

	// Fill out 'dnstap'.
	if (writer->version) {
		dnstap.version.data = writer->version;
		dnstap.version.len = writer->len_version;
		dnstap.has_version = 1;
	}
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = (Dnstap__Message *)msg;

	// Serialize the dnstap frame.
	if (!dt_pack(&dnstap, &data, &len)) {
		return KNOT_ENOMEM;
	}

	// Write the dnstap frame to the output stream.
	if (fstrm_writer_write(writer->fw, data, len) != fstrm_res_success) {
		return KNOT_ERROR;
	}

	// Cleanup.
	free(data);

	return KNOT_EOK;
}
