/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/control/control.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "contrib/wire_ctx.h"

/*! Size of the input and output buffers. */
#ifndef CTL_BUFF_SIZE
#define CTL_BUFF_SIZE		(256 * 1024)
#endif

/*! Default socket operations timeout in milliseconds. */
#define DEFAULT_TIMEOUT		(5 * 1000)

/*! The first data item code. */
#define DATA_CODE_OFFSET	16

/*! Control context structure. */
struct knot_ctl {
	/*! Memory pool context. */
	knot_mm_t mm;
	/*! Network operations timeout. */
	int timeout;
	/*! Server listening socket. */
	int listen_sock;
	/*! Remote server/client socket. */
	int sock;

	/*! The latter read data. */
	knot_ctl_data_t data;

	/*! Write wire context. */
	wire_ctx_t wire_out;
	/*! Read wire context. */
	wire_ctx_t wire_in;

	/*! Write buffer. */
	uint8_t buff_out[CTL_BUFF_SIZE];
	/*! Read buffer. */
	uint8_t buff_in[CTL_BUFF_SIZE];
};

static int type_to_code(knot_ctl_type_t type)
{
	switch (type) {
	case KNOT_CTL_TYPE_END:   return  0;
	case KNOT_CTL_TYPE_DATA:  return  1;
	case KNOT_CTL_TYPE_EXTRA: return  2;
	case KNOT_CTL_TYPE_BLOCK: return  3;
	default:                  return -1;
	}
}

static int code_to_type(uint8_t code)
{
	switch (code) {
	case 0:  return KNOT_CTL_TYPE_END;
	case 1:  return KNOT_CTL_TYPE_DATA;
	case 2:  return KNOT_CTL_TYPE_EXTRA;
	case 3:  return KNOT_CTL_TYPE_BLOCK;
	default: return -1;
	}
}

static bool is_data_type(knot_ctl_type_t type)
{
	switch (type) {
	case KNOT_CTL_TYPE_DATA:
	case KNOT_CTL_TYPE_EXTRA:
		return true;
	default:
		return false;
	}
}

static int idx_to_code(knot_ctl_idx_t idx)
{
	if (idx >= KNOT_CTL_IDX__COUNT) {
		return -1;
	}

	return DATA_CODE_OFFSET + idx;
}

static int code_to_idx(uint8_t code)
{
	if (code <  DATA_CODE_OFFSET ||
	    code >= DATA_CODE_OFFSET + KNOT_CTL_IDX__COUNT) {
		return -1;
	}

	return code - DATA_CODE_OFFSET;
}

static void reset_buffers(knot_ctl_t *ctx)
{
	ctx->wire_out = wire_ctx_init(ctx->buff_out, CTL_BUFF_SIZE);
	ctx->wire_in = wire_ctx_init(ctx->buff_in, 0);
}

static void clean_data(knot_ctl_t *ctx)
{
	mp_flush(ctx->mm.ctx);
	memset(ctx->data, 0, sizeof(ctx->data));
}

static void close_sock(int *sock)
{
	if (*sock < 0) {
		return;
	}

	close(*sock);
	*sock = -1;
}

_public_
knot_ctl_t* knot_ctl_alloc(void)
{
	knot_ctl_t *ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(*ctx));

	mm_ctx_mempool(&ctx->mm, MM_DEFAULT_BLKSIZE);
	ctx->timeout = DEFAULT_TIMEOUT;
	ctx->listen_sock = -1;
	ctx->sock = -1;

	reset_buffers(ctx);

	return ctx;
}

_public_
void knot_ctl_free(knot_ctl_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	close_sock(&ctx->listen_sock);
	close_sock(&ctx->sock);

	clean_data(ctx);

	mp_delete(ctx->mm.ctx);

	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
}

_public_
void knot_ctl_set_timeout(knot_ctl_t *ctx, int timeout_ms)
{
	if (ctx == NULL) {
		return;
	}

	ctx->timeout = (timeout_ms > 0) ? timeout_ms : -1;
}

_public_
int knot_ctl_bind(knot_ctl_t *ctx, const char *path)
{
	if (ctx == NULL || path == NULL) {
		return KNOT_EINVAL;
	}

	// Prepare socket address.
	struct sockaddr_storage addr;
	int ret = sockaddr_set(&addr, AF_UNIX, path, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Bind the socket.
	ctx->listen_sock = net_bound_socket(SOCK_STREAM, (struct sockaddr *)&addr, 0);
	if (ctx->listen_sock < 0) {
		return ctx->listen_sock;
	}

	// Start listening.
	if (listen(ctx->listen_sock, 1) != 0) {
		close_sock(&ctx->listen_sock);
		return knot_map_errno();
	}

	return KNOT_EOK;
}

_public_
void knot_ctl_unbind(knot_ctl_t *ctx)
{
	if (ctx == NULL || ctx->listen_sock < 0) {
		return;
	}

	// Remove the control socket file.
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if (getsockname(ctx->listen_sock, (struct sockaddr *)&addr, &addr_len) == 0) {
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		if (sockaddr_tostr(addr_str, sizeof(addr_str), (struct sockaddr *)&addr) > 0) {
			(void)unlink(addr_str);
		}
	}

	// Close the listening socket.
	close_sock(&ctx->listen_sock);
}

_public_
int knot_ctl_accept(knot_ctl_t *ctx)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	knot_ctl_close(ctx);

	// Control interface.
	struct pollfd pfd = { .fd = ctx->listen_sock, .events = POLLIN };
	int ret = poll(&pfd, 1, -1);
	if (ret <= 0) {
		return knot_map_errno();
	}

	int client = net_accept(ctx->listen_sock, NULL);
	if (client < 0) {
		return client;
	}

	ctx->sock = client;

	reset_buffers(ctx);

	return KNOT_EOK;
}

_public_
int knot_ctl_connect(knot_ctl_t *ctx, const char *path)
{
	if (ctx == NULL || path == NULL) {
		return KNOT_EINVAL;
	}

	// Prepare socket address.
	struct sockaddr_storage addr;
	int ret = sockaddr_set(&addr, AF_UNIX, path, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Connect to socket.
	ctx->sock = net_connected_socket(SOCK_STREAM, (struct sockaddr *)&addr, NULL);
	if (ctx->sock < 0) {
		return ctx->sock;
	}

	reset_buffers(ctx);

	return KNOT_EOK;
}

_public_
void knot_ctl_close(knot_ctl_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	close_sock(&ctx->sock);
}

static int ensure_output(knot_ctl_t *ctx, uint16_t len)
{
	wire_ctx_t *w = &ctx->wire_out;

	// Check for enough available room in the output buffer.
	size_t available = wire_ctx_available(w);
	if (available >= len) {
		return KNOT_EOK;
	}

	// Flush the buffer.
	int ret = net_stream_send(ctx->sock, w->wire, wire_ctx_offset(w),
	                          ctx->timeout);
	if (ret < 0) {
		return ret;
	}

	*w = wire_ctx_init(w->wire, CTL_BUFF_SIZE);

	return KNOT_EOK;
}

static int send_item(knot_ctl_t *ctx, uint8_t code, const char *data, bool flush)
{
	wire_ctx_t *w = &ctx->wire_out;

	// Write the control block code.
	int ret = ensure_output(ctx, sizeof(uint8_t));
	if (ret != KNOT_EOK) {
		return ret;
	}
	wire_ctx_write_u8(w, code);
	if (w->error != KNOT_EOK) {
		return w->error;
	}

	// Control block data is optional.
	if (data != NULL) {
		// Get the data length.
		size_t data_len = strlen(data);
		if (data_len > UINT16_MAX) {
			return KNOT_ERANGE;
		}

		// Write the data length.
		ret = ensure_output(ctx, sizeof(uint16_t));
		if (ret != KNOT_EOK) {
			return ret;
		}
		wire_ctx_write_u16(w, data_len);
		if (w->error != KNOT_EOK) {
			return w->error;
		}

		// Write the data.
		ret = ensure_output(ctx, data_len);
		if (ret != KNOT_EOK) {
			return ret;
		}
		wire_ctx_write(w, (uint8_t *)data, data_len);
		if (w->error != KNOT_EOK) {
			return w->error;
		}
	}

	// Send finalized buffer.
	if (flush && wire_ctx_offset(w) > 0) {
		ret = net_stream_send(ctx->sock, w->wire, wire_ctx_offset(w),
		                      ctx->timeout);
		if (ret < 0) {
			return ret;
		}

		*w = wire_ctx_init(w->wire, CTL_BUFF_SIZE);
	}

	return KNOT_EOK;
}

_public_
int knot_ctl_send(knot_ctl_t *ctx, knot_ctl_type_t type, knot_ctl_data_t *data)
{
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	// Get the type code.
	int code = type_to_code(type);
	if (code == -1) {
		return KNOT_EINVAL;
	}

	// Send unit type.
	int ret = send_item(ctx, code, NULL, !is_data_type(type));
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Send unit data.
	if (is_data_type(type) && data != NULL) {
		// Send all non-empty data items.
		for (knot_ctl_idx_t i = 0; i < KNOT_CTL_IDX__COUNT; i++) {
			const char *value = (*data)[i];
			if (value == NULL) {
				continue;
			}

			ret = send_item(ctx, idx_to_code(i), value, false);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int ensure_input(knot_ctl_t *ctx, uint16_t len)
{
	wire_ctx_t *w = &ctx->wire_in;

	// Check for enough available room in the input buffer.
	size_t available = wire_ctx_available(w);
	if (available >= len) {
		return KNOT_EOK;
	}

	// Move unprocessed data to the beginning of the buffer.
	memmove(w->wire, w->wire + wire_ctx_offset(w), available);

	// Receive enough data.
	while (available < len) {
		int ret = net_stream_recv(ctx->sock, w->wire + available,
		                          CTL_BUFF_SIZE - available,
		                          ctx->timeout);
		if (ret < 0) {
			return ret;
		}
		assert(ret > 0);
		available += ret;
	}

	ctx->wire_in = wire_ctx_init(w->wire, available);

	return KNOT_EOK;
}

static int receive_item_code(knot_ctl_t *ctx, uint8_t *code)
{
	wire_ctx_t *w = &ctx->wire_in;

	// Read the type.
	int ret = ensure_input(ctx, sizeof(uint8_t));
	if (ret != KNOT_EOK) {
		return ret;
	}
	*code = wire_ctx_read_u8(w);
	if (w->error != KNOT_EOK) {
		return w->error;
	}

	return KNOT_EOK;
}

static int receive_item_value(knot_ctl_t *ctx, char **value)
{
	wire_ctx_t *w = &ctx->wire_in;

	// Read value length.
	int ret = ensure_input(ctx, sizeof(uint16_t));
	if (ret != KNOT_EOK) {
		return ret;
	}
	uint16_t data_len = wire_ctx_read_u16(w);
	if (w->error != KNOT_EOK) {
		return w->error;
	}

	// Read the value.
	ret = ensure_input(ctx, data_len);
	if (ret != KNOT_EOK) {
		return ret;
	}
	*value = mm_alloc(&ctx->mm, data_len + 1);
	if (*value == NULL) {
		return KNOT_ENOMEM;
	}
	wire_ctx_read(w, *value, data_len);
	if (w->error != KNOT_EOK) {
		return w->error;
	}
	(*value)[data_len] = '\0';

	return KNOT_EOK;
}

_public_
int knot_ctl_receive(knot_ctl_t *ctx, knot_ctl_type_t *type, knot_ctl_data_t *data)
{
	if (ctx == NULL || type == NULL) {
		return KNOT_EINVAL;
	}

	wire_ctx_t *w = &ctx->wire_in;

	// Reset output variables.
	*type = KNOT_CTL_TYPE_END;
	clean_data(ctx);

	// Read data units until end of message.
	bool have_type = false;
	while (true) {
		uint8_t code;
		int ret = receive_item_code(ctx, &code);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Process unit type.
		int current_type = code_to_type(code);
		if (current_type != -1) {
			if (have_type) {
				// Revert parsed type.
				wire_ctx_skip(w, -sizeof(uint8_t));
				assert(w->error == KNOT_EOK);
				break;
			}

			// Set the unit type.
			*type = current_type;

			if (is_data_type(current_type)) {
				have_type = true;
				continue;
			} else {
				break;
			}
		}

		// Check for data item code.
		int idx = code_to_idx(code);
		if (idx == -1) {
			return KNOT_EINVAL;
		}

		// Store the item data value.
		ret = receive_item_value(ctx, (char **)&ctx->data[idx]);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Set the output data.
	if (data != NULL) {
		memcpy(*data, ctx->data, sizeof(*data));
	}

	return KNOT_EOK;
}
