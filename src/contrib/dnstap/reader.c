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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/errcode.h"

#include "contrib/macros.h"
#include "contrib/dnstap/dnstap.h"
#include "contrib/dnstap/reader.h"

dt_reader_t* dt_reader_create(const char *file_path)
{
	struct fstrm_file_options *fopt = NULL;
	struct fstrm_reader_options *ropt = NULL;
	dt_reader_t *reader = NULL;
	fstrm_res res;

	reader = calloc(1, sizeof(dt_reader_t));
	if (reader == NULL) {
		goto fail;
	}

	// Open reader.
	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, file_path);
	ropt = fstrm_reader_options_init();
	fstrm_reader_options_add_content_type(ropt,
		(const uint8_t *) DNSTAP_CONTENT_TYPE,
		strlen(DNSTAP_CONTENT_TYPE));
	reader->fr = fstrm_file_reader_init(fopt, ropt);
	fstrm_file_options_destroy(&fopt);
	fstrm_reader_options_destroy(&ropt);
	if (reader->fr == NULL) {
		goto fail;
	}
	res = fstrm_reader_open(reader->fr);
	if (res != fstrm_res_success) {
		goto fail;
	}

	return reader;
fail:
	dt_reader_free(reader);
	return NULL;
}

void dt_reader_free(dt_reader_t *reader)
{
	if (reader == NULL) {
		return;
	}

	fstrm_reader_destroy(&reader->fr);
	free(reader);
}

int dt_reader_read(dt_reader_t *reader, Dnstap__Dnstap **d)
{
	fstrm_res res;
	const uint8_t *data = NULL;
	size_t len = 0;

	res = fstrm_reader_read(reader->fr, &data, &len);
	if (res == fstrm_res_success) {
		*d = dnstap__dnstap__unpack(NULL, len, data);
		if (*d == NULL) {
			return KNOT_ENOMEM;
		}
	} else if (res == fstrm_res_failure) {
		return KNOT_ERROR;
	} else if (res == fstrm_res_stop) {
		return KNOT_EOF;
	}

	return KNOT_EOK;
}

void dt_reader_free_frame(dt_reader_t *reader, Dnstap__Dnstap **frame_ptr)
{
	if (!*frame_ptr) {
		return;
	}

	UNUSED(reader);

	dnstap__dnstap__free_unpacked(*frame_ptr, NULL);
	*frame_ptr = NULL;
}
