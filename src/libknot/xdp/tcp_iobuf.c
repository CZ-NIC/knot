/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/xdp/tcp_iobuf.h"

#include "contrib/macros.h"
#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/error.h"
#include "libknot/wire.h"

static void iov_clear(struct iovec *iov)
{
	free(iov->iov_base);
	memset(iov, 0, sizeof(*iov));
}

static void iov_inc(struct iovec *iov, size_t shift)
{
	assert(shift <= iov->iov_len);
	iov->iov_base += shift;
	iov->iov_len -= shift;
}

static size_t tcp_payload_len(const struct iovec *payload)
{
	if (payload->iov_len < 2) {
		return 0;
	}
	return knot_wire_read_u16(payload->iov_base);
}

static void iov_append(struct iovec *what, const struct iovec *with)
{
	// NOTE: what->iov_base must be pre-allocated large enough
	memcpy(what->iov_base + what->iov_len, with->iov_base, with->iov_len);
	what->iov_len += with->iov_len;
}

static knot_tcp_inbufs_upd_res_t *tinbufu_alloc(size_t inbuf_count, size_t first_inbuf)
{
	knot_tcp_inbufs_upd_res_t *res = malloc(sizeof(*res) + inbuf_count * sizeof(struct iovec) + first_inbuf);
	if (res == NULL) {
		return NULL;
	}

	res->next = NULL;
	res->n_inbufs = inbuf_count;
	return res;
}

uint64_t buffer_alloc_size(uint64_t buffer_len)
{
	if (buffer_len == 0) {
		return 0;
	}
	buffer_len -= 1;
	buffer_len |= 0x3f; // the result will be at least 64
	buffer_len |= (buffer_len >> 1);
	buffer_len |= (buffer_len >> 2);
	buffer_len |= (buffer_len >> 4);
	buffer_len |= (buffer_len >> 8);
	buffer_len |= (buffer_len >> 16);
	buffer_len |= (buffer_len >> 32);
	return buffer_len + 1;
}

_public_
int knot_tcp_inbufs_upd(struct iovec *buffer, struct iovec data, bool alloc_bufs,
                        knot_tcp_inbufs_upd_res_t **result, size_t *buffers_total)
{
	knot_tcp_inbufs_upd_res_t *out = NULL;
	struct iovec *cur = NULL;

	if (data.iov_len <= 0) {
		return KNOT_EOK;
	}

	// Finalize size bytes in buffer
	assert(buffer != NULL && result != NULL && buffers_total != NULL);
	if (buffer->iov_len == 1) {
		assert(buffer->iov_base != NULL);
		((uint8_t *)buffer->iov_base)[1] = ((uint8_t *)data.iov_base)[0];
		buffer->iov_len++;
		iov_inc(&data, 1);
		if (data.iov_len <= 0) {
			return KNOT_EOK;
		}
	}

	// find the end of linked list if not already
	while (*result != NULL) {
		result = &(*result)->next;
	}

	// Count space needed for finished segments
	size_t iov_cnt = 0, iov_bytesize = 0, message_len = 0;
	struct iovec data_use = data;
	bool skip_cnt = false;
	if (buffer->iov_len >= 2) {
		message_len = tcp_payload_len(buffer);
		size_t data_offset = message_len - (buffer->iov_len - sizeof(uint16_t));
		if (data_use.iov_len >= data_offset) {
			++iov_cnt;
			iov_bytesize += message_len;
			iov_inc(&data_use, data_offset);
		} else {
			skip_cnt = true;
		}
	}
	if (!skip_cnt) {
		if (alloc_bufs) {
			while (data_use.iov_len >= 2 &&
			       (message_len = tcp_payload_len(&data_use)) <= (data_use.iov_len - sizeof(uint16_t))) {
				++iov_cnt;
				iov_bytesize += message_len;
				iov_inc(&data_use, message_len + sizeof(uint16_t));
			}
		} else {
			while (data_use.iov_len >= 2 &&
			       (message_len = tcp_payload_len(&data_use)) <= (data_use.iov_len - sizeof(uint16_t))) {
				++iov_cnt;
				iov_inc(&data_use, message_len + sizeof(uint16_t));
			}
		}
	}

	// Alloc linked-list node and copy data from `buffer` to output
	if (iov_cnt > 0) {
		out = tinbufu_alloc(iov_cnt, iov_bytesize);
		if (out == NULL) {
			return KNOT_ENOMEM;
		}

		cur = out->inbufs;
		uint8_t *out_buf_ptr = (uint8_t *)(cur + iov_cnt);
		data_use = data;
		if (buffer->iov_len >= 2) { // at least some data in buffer
			struct iovec bf = {
				.iov_base = buffer->iov_base + sizeof(uint16_t),
				.iov_len = buffer->iov_len - sizeof(uint16_t)
			};
			cur->iov_base = out_buf_ptr;
			cur->iov_len = 0;
			data_use.iov_base = data.iov_base;
			data_use.iov_len = tcp_payload_len(buffer) - bf.iov_len;
			iov_append(cur, &bf);
			iov_append(cur, &data_use);
			iov_inc(&data, data_use.iov_len);
			out_buf_ptr = cur->iov_base + cur->iov_len;
			++cur;
			*buffers_total -= buffer_alloc_size(buffer->iov_len);
			iov_clear(buffer);
		}

		if (alloc_bufs) {
			for (; cur != out->inbufs + iov_cnt; ++cur) {
				cur->iov_base = out_buf_ptr;
				cur->iov_len = 0;
				data_use.iov_len = tcp_payload_len(&data);
				iov_inc(&data, 2);
				data_use.iov_base = data.iov_base;
				iov_append(cur, &data_use);
				iov_inc(&data, data_use.iov_len);
				out_buf_ptr = cur->iov_base + cur->iov_len;
			}
		} else {
			for (; cur != out->inbufs + iov_cnt; ++cur) {
				cur->iov_len = tcp_payload_len(&data);
				iov_inc(&data, 2);
				cur->iov_base = data.iov_base;
				iov_inc(&data, cur->iov_len);
			}
		}
	}

	// store the final incomplete payload to buffer
	if (data.iov_len > 0) {
		size_t buffer_original_size = buffer_alloc_size(buffer->iov_len);
		size_t bufalloc = buffer_alloc_size(buffer->iov_len + data.iov_len);
		if (buffer_original_size < bufalloc) {
			void *newbuf = realloc(buffer->iov_base, bufalloc);
			if (newbuf == NULL) {
				free(buffer->iov_base);
				buffer->iov_base = NULL;
				free(out);
				return KNOT_ENOMEM;
			}
			buffer->iov_base = newbuf;
			*buffers_total += bufalloc - buffer_original_size;
		}
		iov_append(buffer, &data);
	}

	*result = out;

	return KNOT_EOK;
}

_public_
int knot_tcp_outbufs_add(knot_tcp_outbuf_t **bufs, uint8_t *data, size_t len,
                         bool ignore_lastbyte, uint32_t mss, size_t *outbufs_total)
{
	if (len > UINT16_MAX) {
		return KNOT_ELIMIT;
	}
	knot_tcp_outbuf_t **end = bufs;
	while (*end != NULL) { // NOTE: this can be optimized by adding "end" pointer for the price of larger knot_tcp_conn_t struct
		end = &(*end)->next;
	}
	uint16_t prefix = htobe16(len), prefix_len = sizeof(prefix);
	while (len > 0) {
		uint16_t newlen = MIN(len + prefix_len, mss);
		knot_tcp_outbuf_t *newob = calloc(1, sizeof(*newob) + newlen);
		if (newob == NULL) {
			return KNOT_ENOMEM;
		}
		*outbufs_total += sizeof(*newob) + newlen;
		newob->len = newlen;
		if (ignore_lastbyte) {
			newob->len--;
		}
		memcpy(newob->bytes, &prefix, prefix_len);
		memcpy(newob->bytes + prefix_len, data, newlen - prefix_len);

		*end = newob;
		end = &newob->next;

		data += newlen - prefix_len;
		len -= newlen - prefix_len;

		prefix_len = 0;
	}
	return KNOT_EOK;
}

static bool seqno_lower(uint32_t seqno, uint32_t ackno, uint32_t ackno_min)
{
	if (ackno_min <= ackno) {
		return (seqno >= ackno_min && seqno <= ackno);
	} else {
		return (seqno >= ackno_min || seqno <= ackno);
	}
}

_public_
void knot_tcp_outbufs_ack(knot_tcp_outbuf_t **bufs, uint32_t ackno, size_t *outbufs_total)
{
	uint32_t ackno_min = ackno - (UINT32_MAX / 2); // FIXME better?
	while (*bufs != NULL && (*bufs)->sent && seqno_lower((*bufs)->seqno + (*bufs)->len, ackno, ackno_min)) {
		knot_tcp_outbuf_t *tofree = *bufs;
		*bufs = tofree->next;
		*outbufs_total -= tofree->len + sizeof(*tofree);
		free(tofree);
	}
}

_public_
void knot_tcp_outbufs_can_send(knot_tcp_outbuf_t *bufs, ssize_t window_size, bool resend,
                               knot_tcp_outbuf_t **send_start, size_t *send_count)
{
	*send_count = 0;
	*send_start = bufs;
	while (*send_start != NULL && (*send_start)->sent && !resend) {
		window_size -= (*send_start)->len;
		*send_start = (*send_start)->next;
	}

	knot_tcp_outbuf_t *can_send = *send_start;
	while (can_send != NULL && window_size >= can_send->len) {
		(*send_count)++;
		window_size -= can_send->len;
		can_send = can_send->next;
	}
}

_public_
size_t knot_tcp_outbufs_usage(knot_tcp_outbuf_t *bufs)
{
	size_t res = 0;
	for (knot_tcp_outbuf_t *i = bufs; i != NULL; i = i->next) {
		res += i->len + sizeof(*i);
	}
	return res;
}
