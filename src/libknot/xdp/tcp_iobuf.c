/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/xdp/tcp_iobuf.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/macros.h"
#include "libknot/error.h"

static size_t req_len(void *p)
{
	uint16_t *p16 = p;
	return be16toh(*p16) + sizeof(*p16);
}

size_t knot_tcp_pay_len(const struct iovec *payload)
{
	assert(payload->iov_len >= 2);
	return req_len(payload->iov_base);
}

int knot_tcp_input_buffers(struct iovec *buffer, struct iovec *data,
                           struct iovec *data_tofree, size_t *buffers_total)
{
	memset(data_tofree, 0, sizeof(*data_tofree));
	if (data->iov_len < 1) {
		return KNOT_EOK;
	}
	if (buffer->iov_len == 1) {
		((uint8_t *)buffer->iov_base)[1] = ((uint8_t *)data->iov_base)[0];
		buffer->iov_len++;
		data->iov_base++;
		data->iov_len--;
		if (data->iov_len < 1) {
			return KNOT_EOK;
		}
	}
	if (buffer->iov_len > 0) {
		size_t buffer_req = knot_tcp_pay_len(buffer);
		assert(buffer_req > buffer->iov_len);
		size_t data_use = buffer_req - buffer->iov_len;
		if (data_use <= data->iov_len) { // usable payload combined from buffer and data ---> data_tofree
			data_tofree->iov_len = buffer_req;
			data_tofree->iov_base = realloc(buffer->iov_base, buffer_req);
			if (data_tofree->iov_base == NULL) {
				return KNOT_ENOMEM;
			}
			memcpy(data_tofree->iov_base + buffer->iov_len, data->iov_base, data_use);
			*buffers_total -= buffer->iov_len;
			buffer->iov_base = NULL;
			buffer->iov_len = 0;
			data->iov_base += data_use;
			data->iov_len -= data_use;
		} else { // just extend the buffer with data
			void *bufnew = realloc(buffer->iov_base, buffer->iov_len + data->iov_len);
			if (bufnew == NULL) {
				return KNOT_ENOMEM;
			}
			buffer->iov_base = bufnew;
			memcpy(buffer->iov_base + buffer->iov_len, data->iov_base, data->iov_len);
			*buffers_total += data->iov_len;
			buffer->iov_len += data->iov_len;
			data->iov_base += data->iov_len;
			data->iov_len = 0;
		}
	}

	// skip whole usable payloads in data
	struct iovec data_end = *data;
	size_t data_req;
	while (data_end.iov_len > 1 && (data_req = knot_tcp_pay_len(&data_end)) <= data_end.iov_len) {
		data_end.iov_base += data_req;
		data_end.iov_len -= data_req;
	}

	// store the final incomplete payload to buffer
	if (data_end.iov_len > 0) {
		assert(buffer->iov_base == NULL);
		buffer->iov_base = malloc(MAX(data_end.iov_len, 2));
		if (buffer->iov_base == NULL) {
			free(data_tofree->iov_base);
			memset(data_tofree, 0, sizeof(*data_tofree));
			return KNOT_ENOMEM;
		}
		*buffers_total += MAX(data_end.iov_len, 2);
		buffer->iov_len = data_end.iov_len;
		memcpy(buffer->iov_base, data_end.iov_base, data_end.iov_len);
		data->iov_len -= data_end.iov_len;
	}
	return KNOT_EOK;
}
