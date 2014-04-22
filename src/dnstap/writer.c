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

#include <arpa/inet.h>                  // htonl
#include <errno.h>
#include <stdint.h>                     // uint8_t, uint32_t
#include <stdio.h>                      // fopen, fwrite
#include <stdlib.h>                     // calloc, free
#include <string.h>                     // strdup

#include "common/errcode.h"
#include "libknot/common.h"

#include "dnstap/dnstap.pb-c.h"
#include "dnstap/dnstap.h"
#include "dnstap/writer.h"

#define DNSTAP_INITIAL_BUF_SIZE         256

static int dt_writer_write_control(dt_writer_t *writer,
                                   fstrm_control_type type)
{
	fstrm_res res;

	// Encode the control frame.
	res = fstrm_control_set_type(writer->control, type);
	if (res != fstrm_res_success) {
		return KNOT_ERROR;
	}

	// Write the control frame.
	if (writer->fp != NULL) {
		uint8_t frame[FSTRM_MAX_CONTROL_FRAME_LENGTH];
		size_t len = sizeof(frame);

		res = fstrm_control_encode(writer->control, frame, &len,
                                           FSTRM_CONTROL_FLAG_WITH_HEADER);
		if (res != fstrm_res_success) {
			return KNOT_ERROR;
		}
		fwrite(frame, len, 1, writer->fp);
	}

	return KNOT_EOK;
}

dt_writer_t* dt_writer_create(const char *file_name, const char *version)
{
	dt_writer_t *writer = NULL;
	fstrm_res res;
	
	writer = calloc(1, sizeof(dt_writer_t));
	if (writer == NULL) {
		goto fail;
	}

	// Set "version".
	if (version != NULL) {
		writer->len_version = strlen(version);
		writer->version = (uint8_t *)strdup(version);
		if (!writer->version) {
			goto fail;
		}
	}

	// Open file.
	writer->fp = fopen(file_name, "w");
	if (writer->fp == NULL) {
		goto fail;
	}

	// Initialize the control frame object.
	writer->control = fstrm_control_init();
	res = fstrm_control_set_field_content_type(writer->control,
		(const uint8_t *) DNSTAP_CONTENT_TYPE,
		strlen(DNSTAP_CONTENT_TYPE));
	if (res != fstrm_res_success) {
		goto fail;
	}

	// Write the START control frame.
	if (dt_writer_write_control(writer, FSTRM_CONTROL_START) != KNOT_EOK) {
		goto fail;
	}

	return writer;
fail:
	dt_writer_free(writer);
	return NULL;
}

int dt_writer_close(dt_writer_t *writer)
{
	FILE *fp;
	int rv = KNOT_EOK;

	// Write the STOP control frame.
	if (writer->fp != NULL) {
		rv = dt_writer_write_control(writer, FSTRM_CONTROL_STOP);
	}

	// Close file.
	fp = writer->fp;
	writer->fp = NULL;
	if (fp != NULL) {
		if (fclose(fp) != 0) {
			return knot_map_errno(errno);
		}
	}

	return rv;
}

int dt_writer_free(dt_writer_t *writer)
{
	int rv = KNOT_EOK;
	if (writer != NULL) {
		rv = dt_writer_close(writer);
		fstrm_control_destroy(&writer->control);
		free(writer->version);
		free(writer);
	}
	return rv;
}

int dt_writer_write(dt_writer_t *writer, const ProtobufCMessage *msg)
{
	uint32_t be_len;
	size_t len;
	uint8_t *data;
	Dnstap__Dnstap dnstap = DNSTAP__DNSTAP__INIT;

	if (writer->fp == NULL)
		return KNOT_EOK;

	// Only handle dnstap/Message.
	if (knot_unlikely(msg->descriptor != &dnstap__message__descriptor))
		return KNOT_EINVAL;

	// Fill out 'dnstap'.
	if (writer->version) {
		dnstap.version.data = writer->version;
		dnstap.version.len = writer->len_version;
		dnstap.has_version = 1;
	}
	dnstap.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dnstap.message = (Dnstap__Message *)msg;

	// Serialize the dnstap frame.
	if (!dt_pack(&dnstap, &data, &len))
		return KNOT_ENOMEM;

	// Write the dnstap frame to the output stream.
	be_len = htonl(len);
	fwrite(&be_len, sizeof(be_len), 1, writer->fp);
	fwrite(data, len, 1, writer->fp);

	// Cleanup.
	free(data);

	return KNOT_EOK;
}
