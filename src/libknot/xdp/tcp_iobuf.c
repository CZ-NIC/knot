/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*! \brief Strip 2-byte length prefix from a payload. */
static void iov_inc2(struct iovec *iov)
{
	iov_inc(iov, sizeof(uint16_t));
}

static size_t tcp_payload_len(const struct iovec *payload)
{
	assert(payload->iov_len >= 2);
	uint16_t val;
	memcpy(&val, payload->iov_base, sizeof(val));
	return be16toh(val) + sizeof(val);
}

static bool iov_inc_pf(struct iovec *iov)
{
	size_t shift = tcp_payload_len(iov);
	if (iov->iov_len >= shift) {
		iov_inc(iov, shift);
		return true;
	} else {
		return false;
	}
}

static size_t iov_count(const struct iovec *iov, size_t *out_data)
{
	size_t res = 0;
	struct iovec tmp = *iov;
	while (tmp.iov_len >= sizeof(uint16_t)) {
		size_t shift = tcp_payload_len(iov);
		if (tmp.iov_len < shift) {
			return res;
		}
		res++;
		if (out_data != NULL) {
			*out_data += shift;
		}
		iov_inc(&tmp, shift);
	}
	return res;
}

static void iov_append(struct iovec *what, const struct iovec *with)
{
	// NOTE: what->iov_base must be pre-allocated large enough
	memcpy(what->iov_base + what->iov_len, with->iov_base, with->iov_len);
	what->iov_len += with->iov_len;
}

static knot_tinbufu_res_t *tinbufu_alloc(size_t inbuf_count, size_t first_inbuf)
{
	knot_tinbufu_res_t *res = malloc(sizeof(*res) + inbuf_count*sizeof(*res->inbufs) + first_inbuf);
	if (res == NULL) {
		return NULL;
	}

	res->next = NULL;
	res->n_inbufs = inbuf_count;
	res->inbufs = (void *)(res + 1);
	res->inbufs[0].iov_base = (void *)(res->inbufs + inbuf_count);
	res->inbufs[0].iov_len = 0;
	return res;
}

uint64_t buffer_alloc_size(uint64_t buffer_len)
{
	if (buffer_len == 0) {
		return 0;
	}
	uint64_t x = buffer_len - 1;
	x |= 0x3f; // the result will be at least 64
	x |= (x >> 1);
	x |= (x >> 2);
	x |= (x >> 4);
	x |= (x >> 8);
	x |= (x >> 16);
	x |= (x >> 32);
	return x + 1; // closest higher (than buffer_len-1) power of two
}

_public_
int knot_tcp_inbuf_update(struct iovec *buffer, struct iovec data, bool alloc_bufs,
                          knot_tinbufu_res_t **result, size_t *buffers_total)
{
	knot_tinbufu_res_t *out = NULL;
	struct iovec *cur = NULL;

	if (data.iov_len <= 0) {
		return KNOT_EOK;
	}
	if (buffer->iov_len == 1) {
		((uint8_t *)buffer->iov_base)[1] = ((uint8_t *)data.iov_base)[0];
		buffer->iov_len++;
		iov_inc(&data, 1);
		if (data.iov_len < 1) {
			return KNOT_EOK;
		}
	}

	// find the end of linked list if not already
	while (*result != NULL) {
		result = &(*result)->next;
	}

	if (buffer->iov_len > 0) {
		size_t buffer_req = tcp_payload_len(buffer);
		size_t bufusage = buffer_alloc_size(buffer->iov_len);
		assert(buffer_req > buffer->iov_len);
		struct iovec data_use = { data.iov_base, buffer_req - buffer->iov_len };
		if (data_use.iov_len <= data.iov_len) { // usable payload combined from buffer and data ---> res[0] allocated tohether with res
			iov_inc(&data, data_use.iov_len);

			size_t bufssiz = 0, nbufs = 1 + iov_count(&data, &bufssiz);
			out = tinbufu_alloc(nbufs, buffer_req + (alloc_bufs ? bufssiz : 0));
			if (out == NULL) {
				return KNOT_ENOMEM;
			}
			cur = out->inbufs;
			iov_append(cur, buffer);
			iov_append(cur, &data_use);
			assert(cur->iov_len == buffer_req);
			iov_inc2(cur);

			cur++;
			*buffers_total -= bufusage;
			iov_clear(buffer);
		} else { // just extend the buffer with data
			size_t bufnewlen = buffer->iov_len + data.iov_len;
			if (bufnewlen > bufusage) {
				size_t bufalloc = buffer_alloc_size(bufnewlen);
				void *bufnew = realloc(buffer->iov_base, bufalloc);
				if (bufnew == NULL) {
					return KNOT_ENOMEM;
				}
				buffer->iov_base = bufnew;
				*buffers_total += bufalloc - bufusage;
			}
			iov_append(buffer, &data);
			return KNOT_EOK;
		}
	} else { // just allocate res
		size_t bufssiz = 0, res_count = iov_count(&data, &bufssiz);
		if (res_count > 0) {
			out = tinbufu_alloc(res_count, alloc_bufs ? bufssiz : 0);
			if (out == NULL) {
				return KNOT_ENOMEM;
			}
			cur = out->inbufs;
		}
	}

	void *last;
	while (data.iov_len > 1) {
		last = data.iov_base;
		if (!iov_inc_pf(&data)) {
			break;
		}
		assert(cur);
		if (!alloc_bufs) {
			cur->iov_base = last;
		} else if (cur != out->inbufs) {
			cur->iov_base = (cur-1)->iov_base + (cur-1)->iov_len;
		}
		cur->iov_len = data.iov_base - last;
		if (alloc_bufs) {
			memcpy(cur->iov_base, last, cur->iov_len);
		}
		iov_inc2(cur);
		cur++;
	}

	// store the final incomplete payload to buffer
	if (data.iov_len > 0) {
		assert(buffer->iov_base == NULL);
		size_t bufalloc = buffer_alloc_size(data.iov_len);
		buffer->iov_base = malloc(bufalloc);
		if (buffer->iov_base == NULL) {
			free(out);
			return KNOT_ENOMEM;
		}
		*buffers_total += bufalloc;
		buffer->iov_len = 0;
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
