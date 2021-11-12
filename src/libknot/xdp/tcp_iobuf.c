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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/xdp/tcp_iobuf.h"
#include "libknot/xdp/tcp.h" // just tcp_outbufs_t
#include "libknot/error.h"
#include "contrib/macros.h"

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

static size_t iov_count(const struct iovec *iov)
{
	size_t res = 0;
	struct iovec tmp = *iov;
	while (tmp.iov_len >= sizeof(uint16_t) && iov_inc_pf(&tmp)) {
		res++;
	}
	return res;
}

static void iov_append(struct iovec *what, const struct iovec *with)
{
	// NOTE: what->iov_base must be pre-allocated large enough
	memcpy(what->iov_base + what->iov_len, with->iov_base, with->iov_len);
	what->iov_len += with->iov_len;
}

int tcp_inbuf_update(struct iovec *buffer, struct iovec data,
                     struct iovec **inbufs, size_t *inbufs_count,
                     size_t *buffers_total)
{
	size_t res_count = 0;
	struct iovec *res = NULL, *cur = NULL;

	*inbufs = NULL;
	*inbufs_count = 0;

	if (data.iov_len < 1) {
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
	if (buffer->iov_len > 0) {
		size_t buffer_req = tcp_payload_len(buffer);
		assert(buffer_req > buffer->iov_len);
		struct iovec data_use = { data.iov_base, buffer_req - buffer->iov_len };
		if (data_use.iov_len <= data.iov_len) { // usable payload combined from buffer and data ---> res[0] allocated tohether with res
			iov_inc(&data, data_use.iov_len);

			res_count = 1 + iov_count(&data);
			res = malloc(res_count * sizeof(*res) + buffer_req);
			if (res == NULL) {
				return KNOT_ENOMEM;
			}
			res[0].iov_base = (void *)(res + res_count);
			res[0].iov_len = 0;
			iov_append(&res[0], buffer);
			iov_append(&res[0], &data_use);
			assert(res[0].iov_len == buffer_req);
			iov_inc2(&res[0]);

			cur = &res[1];
			*buffers_total -= buffer->iov_len;
			iov_clear(buffer);
		} else { // just extend the buffer with data
			void *bufnew = realloc(buffer->iov_base, buffer->iov_len + data.iov_len);
			if (bufnew == NULL) {
				return KNOT_ENOMEM;
			}
			buffer->iov_base = bufnew;
			iov_append(buffer, &data);
			*buffers_total += data.iov_len;
			return KNOT_EOK;
		}
	} else { // just allocate res
		res_count = iov_count(&data);
		if (res_count > 0) {
			res = malloc(res_count * sizeof(*res));
			if (res == NULL) {
				return KNOT_ENOMEM;
			}
			cur = &res[0];
		}
	}

	void *last;
	while (data.iov_len > 1) {
		last = data.iov_base;
		if (!iov_inc_pf(&data)) {
			break;
		}
		cur->iov_base = last;
		cur->iov_len = data.iov_base - last;
		iov_inc2(cur);
		cur++;
	}
	assert(cur == res + res_count);

	// store the final incomplete payload to buffer
	if (data.iov_len > 0) {
		assert(buffer->iov_base == NULL);
		buffer->iov_base = malloc(MAX(data.iov_len, 2));
		if (buffer->iov_base == NULL) {
			free(res);
			return KNOT_ENOMEM;
		}
		*buffers_total += MAX(data.iov_len, 2);
		buffer->iov_len = 0;
		iov_append(buffer, &data);
	}

	*inbufs = res;
	*inbufs_count = res_count;

	return KNOT_EOK;
}

int tcp_outbufs_add(struct tcp_outbufs *ob, uint8_t *data, size_t len,
                    bool ignore_lastbyte, uint32_t mss, size_t *outbufs_total)
{
	if (len > UINT16_MAX) {
		return KNOT_ELIMIT;
	}
	struct tcp_outbuf **end = &ob->bufs;
	while (*end != NULL) { // NOTE: this can be optimized by adding "end" pointer for the price of larger knot_tcp_conn_t struct
		end = &(*end)->next;
	}
	uint16_t prefix = htobe16(len), prefix_len = sizeof(prefix);
	while (len > 0) {
		uint16_t newlen = MIN(len + prefix_len, mss);
		struct tcp_outbuf *newob = calloc(1, sizeof(*newob) + newlen);
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

void tcp_outbufs_ack(struct tcp_outbufs *ob, uint32_t ackno, size_t *outbufs_total)
{
	uint32_t ackno_min = ackno - (UINT32_MAX / 2); // FIXME better?
	while (ob->bufs != NULL && ob->bufs->sent && seqno_lower(ob->bufs->seqno + ob->bufs->len, ackno, ackno_min)) {
		struct tcp_outbuf *tofree = ob->bufs;
		ob->bufs = tofree->next;
		*outbufs_total -= tofree->len + sizeof(*tofree);
		free(tofree);
	}
}

void tcp_outbufs_can_send(struct tcp_outbufs *ob, ssize_t window_size, bool resend,
                          struct tcp_outbuf **send_start, size_t *send_count)
{
	*send_count = 0;
	*send_start = ob->bufs;
	while (*send_start != NULL && (*send_start)->sent && !resend) {
		window_size -= (*send_start)->len;
		*send_start = (*send_start)->next;
	}

	struct tcp_outbuf *can_send = *send_start;
	while (can_send != NULL && window_size >= can_send->len) {
		(*send_count)++;
		window_size -= can_send->len;
		can_send = can_send->next;
	}
}

size_t tcp_outbufs_usage(struct tcp_outbufs *ob)
{
	size_t res = 0;
	for (struct tcp_outbuf *i = ob->bufs; i != NULL; i = i->next) {
		res += i->len + sizeof(*i);
	}
	return res;
}
