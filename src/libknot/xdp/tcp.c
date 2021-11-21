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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libknot/xdp/tcp.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "libdnssec/random.h"
#include "contrib/macros.h"
#include "contrib/openbsd/siphash.h"
#include "contrib/ucw/lists.h"

static uint32_t get_timestamp(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	uint64_t res = (uint64_t)t.tv_sec * 1000000;
	res += (uint64_t)t.tv_nsec / 1000;
	return res & 0xffffffff; // overflow does not matter since we are working with differences
}

static size_t sockaddr_data_len(const struct sockaddr_in6 *rem, const struct sockaddr_in6 *loc)
{
	assert(rem->sin6_family == loc->sin6_family);
	if (rem->sin6_family == AF_INET) {
		return offsetof(struct sockaddr_in, sin_zero);
	} else {
		assert(rem->sin6_family == AF_INET6);
		return offsetof(struct sockaddr_in6, sin6_scope_id);
	}
}

static uint64_t hash_four_tuple(const struct sockaddr_in6 *rem, const struct sockaddr_in6 *loc,
                                knot_tcp_table_t *table)
{
	size_t socka_data_len = sockaddr_data_len(rem, loc);
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, (const SIPHASH_KEY *)(table->hash_secret));
	SipHash24_Update(&ctx, rem, socka_data_len);
	SipHash24_Update(&ctx, loc, socka_data_len);
	return SipHash24_End(&ctx);
}

static list_t *tcp_table_timeout(knot_tcp_table_t *table)
{
	return (list_t *)&table->conns[table->size];
}

static node_t *tcp_conn_node(knot_tcp_conn_t *conn)
{
	return (node_t *)&conn->list_node_placeholder;
}

_public_
knot_tcp_table_t *knot_tcp_table_new(size_t size)
{
	knot_tcp_table_t *table = calloc(1, sizeof(*table) + sizeof(list_t) +
	                                    size * sizeof(table->conns[0]));
	if (table == NULL) {
		return table;
	}

	table->size = size;
	init_list(tcp_table_timeout(table));

	assert(sizeof(table->hash_secret) == sizeof(SIPHASH_KEY));
	table->hash_secret[0] = dnssec_random_uint64_t();
	table->hash_secret[1] = dnssec_random_uint64_t();

	return table;
}

_public_
void knot_tcp_table_free(knot_tcp_table_t *table)
{
	if (table != NULL) {
		knot_tcp_conn_t *conn, *next;
		WALK_LIST_DELSAFE(conn, next, *tcp_table_timeout(table)) {
			free(conn);
		}
		free(table);
	}
}

static knot_tcp_conn_t **tcp_table_lookup(const struct sockaddr_in6 *rem,
                                          const struct sockaddr_in6 *loc,
                                          uint64_t *hash, knot_tcp_table_t *table)
{
	*hash = hash_four_tuple(rem, loc, table);
	size_t sdl = sockaddr_data_len(rem, loc);
	knot_tcp_conn_t **res = table->conns + (*hash % table->size);
	while (*res != NULL) {
		if (memcmp(&(*res)->ip_rem, rem, sdl) == 0 &&
		    memcmp(&(*res)->ip_loc, loc, sdl) == 0) {
			rem_node(tcp_conn_node(*res));
			add_tail(tcp_table_timeout(table), tcp_conn_node(*res));
			break;
		}
		res = &(*res)->next;
	}
	return res;
}

static void tcp_table_del_conn(knot_tcp_conn_t **todel)
{
	knot_tcp_conn_t *conn = *todel;
	if (conn != NULL) {
		*todel = conn->next; // remove from conn-table linked list
		rem_node(tcp_conn_node(conn)); // remove from timeout double-linked list
		free(conn->inbuf.iov_base);
		free(conn);
	}
}

static void tcp_table_del(knot_tcp_conn_t **todel, knot_tcp_table_t *table)
{
	assert(table->usage > 0);
	table->inbufs_total -= (*todel)->inbuf.iov_len;
	tcp_table_del_conn(todel);
	table->usage--;
}

static void tcp_table_del_lookup(knot_tcp_conn_t *todel, knot_tcp_table_t *table)
{
	// re-lookup is needed to find the **pointer in the table
	uint64_t unused_hash;
	knot_tcp_conn_t **pconn = tcp_table_lookup(&todel->ip_rem, &todel->ip_loc,
	                                           &unused_hash, table);
	assert(*pconn == todel);
	tcp_table_del(pconn, table);
}

// WARNING you shall ensure that it's not in the table already!
static int tcp_table_add(knot_xdp_msg_t *msg, uint64_t hash, knot_tcp_table_t *table,
                         knot_tcp_conn_t **res)
{
	knot_tcp_conn_t *c = malloc(sizeof(*c));
	if (c == NULL) {
		return KNOT_ENOMEM;
	}
	knot_tcp_conn_t **addto = table->conns + (hash % table->size);

	memcpy(&c->ip_rem, &msg->ip_from, sizeof(c->ip_rem));
	memcpy(&c->ip_loc, &msg->ip_to,   sizeof(c->ip_loc));

	memcpy(&c->last_eth_rem, &msg->eth_from, sizeof(c->last_eth_rem));
	memcpy(&c->last_eth_loc, &msg->eth_to,   sizeof(c->last_eth_loc));

	c->seqno = msg->seqno;
	c->ackno = msg->ackno;
	c->acked = msg->ackno;

	c->last_active = get_timestamp();
	add_tail(tcp_table_timeout(table), tcp_conn_node(c));

	c->state = XDP_TCP_NORMAL;
	memset(&c->inbuf, 0, sizeof(c->inbuf));

	c->next = *addto;
	*addto = c;

	table->usage++;
	*res = c;
	return KNOT_EOK;
}

knot_dynarray_define(knot_tcp_relay, knot_tcp_relay_t, DYNARRAY_VISIBILITY_PUBLIC)

static bool check_seq_ack(const knot_xdp_msg_t *msg, const knot_tcp_conn_t *conn)
{
	if (conn == NULL || conn->seqno != msg->seqno) {
		return false;
	}

	if (conn->acked <= conn->ackno) { // ackno does not wrap around uint32
		return (msg->ackno >= conn->acked && msg->ackno <= conn->ackno);
	} else { // this is more tricky
		return (msg->ackno >= conn->acked || msg->ackno <= conn->ackno);
	}
}

_public_
int knot_tcp_relay(knot_xdp_socket_t *socket, knot_xdp_msg_t msgs[], uint32_t msg_count,
                   knot_tcp_table_t *tcp_table, knot_tcp_table_t *syn_table,
                   knot_tcp_relay_dynarray_t *relays, uint32_t *ack_errors)
{
	if (msg_count == 0) {
		return KNOT_EOK;
	}
	if (socket == NULL || msgs == NULL || tcp_table == NULL || relays == NULL) {
		return KNOT_EINVAL;
	}

	knot_xdp_send_prepare(socket);

	knot_xdp_msg_t acks[msg_count];
	uint32_t n_acks = 0;
	int ret = KNOT_EOK;

#define resp_ack(msg, flag) \
	{ \
		knot_xdp_msg_t *ack = &acks[n_acks++]; \
		int ackret = knot_xdp_reply_alloc(socket, (msg), ack); \
		if (ackret != KNOT_EOK) { \
			if (ack_errors != NULL) (*ack_errors)++; \
			n_acks--; \
			continue; \
		} \
		ack->payload.iov_len = 0; \
		ack->flags |= (flag); \
	}

	for (size_t i = 0; i < msg_count && ret == KNOT_EOK; i++) {
		knot_xdp_msg_t *msg = &msgs[i];
		if (!(msg->flags & KNOT_XDP_MSG_TCP)) {
			continue;
		}

		uint64_t conn_hash;
		knot_tcp_conn_t **conn = tcp_table_lookup(&msg->ip_from, &msg->ip_to,
		                                          &conn_hash, tcp_table);
		bool seq_ack_match = check_seq_ack(msg, *conn);
		if (seq_ack_match) {
			assert((*conn)->mss != 0);
			(*conn)->seqno = knot_tcp_next_seqno(msg);
			memcpy((*conn)->last_eth_rem, msg->eth_from, sizeof((*conn)->last_eth_rem));
			memcpy((*conn)->last_eth_loc, msg->eth_to, sizeof((*conn)->last_eth_loc));
			(*conn)->last_active = get_timestamp();
			if (msg->flags & KNOT_XDP_MSG_ACK) {
				(*conn)->acked = msg->ackno;
			}
		}

		knot_tcp_relay_t relay = { .msg = msg, .conn = *conn };

		// process incoming data
		if (seq_ack_match && (msg->flags & KNOT_XDP_MSG_ACK) && msg->payload.iov_len > 0) {
			resp_ack(msg, KNOT_XDP_MSG_ACK);
			relay.action = XDP_TCP_DATA;

			struct iovec msg_payload = msg->payload, tofree;
			ret = tcp_inbuf_update(&(*conn)->inbuf, &msg_payload,
			                       &tofree, &tcp_table->inbufs_total);

			if (tofree.iov_len > 0 && ret == KNOT_EOK) {
				relay.data.iov_base = tofree.iov_base + sizeof(uint16_t);
				relay.data.iov_len = tofree.iov_len - sizeof(uint16_t);
				relay.free_data = XDP_TCP_FREE_PREFIX;
				if (knot_tcp_relay_dynarray_add(relays, &relay) == NULL) {
					ret = KNOT_ENOMEM;
				}
				relay.free_data = XDP_TCP_FREE_NONE;
			}
			while (msg_payload.iov_len > 0 && ret == KNOT_EOK) {
				size_t dns_len = tcp_payload_len(&msg_payload);
				assert(dns_len >= msg_payload.iov_len);
				relay.data.iov_base = msg_payload.iov_base + sizeof(uint16_t);
				relay.data.iov_len = dns_len - sizeof(uint16_t);
				if (knot_tcp_relay_dynarray_add(relays, &relay) == NULL) {
					ret = KNOT_ENOMEM;
				}

				msg_payload.iov_base += dns_len;
				msg_payload.iov_len -= dns_len;
			}
		}

		// process TCP connection state
		switch (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK |
		                      KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_RST)) {
		case KNOT_XDP_MSG_SYN:
		case (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK):
			if (*conn == NULL) {
				bool synack = (msg->flags & KNOT_XDP_MSG_ACK);
				resp_ack(msg, synack ? KNOT_XDP_MSG_ACK :
				                       (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK));
				relay.action = synack ? XDP_TCP_ESTABLISH : XDP_TCP_SYN;
				ret = tcp_table_add(msg, conn_hash,
				                    (syn_table == NULL || synack) ? tcp_table : syn_table,
				                    &relay.conn);
				if (knot_tcp_relay_dynarray_add(relays, &relay) == NULL) {
					ret = KNOT_ENOMEM;
				}
				if (ret == KNOT_EOK) {
					relay.conn->state = XDP_TCP_ESTABLISHING;
					relay.conn->seqno++;
					relay.conn->mss = MAX(msg->mss, 536); // minimal MSS, most importantly not zero!
					relay.conn->acked = acks[n_acks - 1].seqno;
					relay.conn->ackno = relay.conn->acked + (synack ? 0 : 1);
				}
			} else {
				resp_ack(msg, KNOT_XDP_MSG_RST); // TODO consider resetting the OLD conn and accepting new one
			}
			break;
		case KNOT_XDP_MSG_ACK:
			if (!seq_ack_match) {
				uint64_t syn_hash;
				if (syn_table != NULL && msg->payload.iov_len == 0 &&
				    *(conn = tcp_table_lookup(&msg->ip_from, &msg->ip_to, &syn_hash, syn_table)) != NULL &&
				     check_seq_ack(msg, *conn)) {
					tcp_table_del(conn, syn_table);
					*conn = NULL;
					relay.action = XDP_TCP_ESTABLISH;
					ret = tcp_table_add(msg, conn_hash, tcp_table, &relay.conn);
					if (ret == KNOT_EOK && knot_tcp_relay_dynarray_add(relays, &relay) == NULL) {
						ret = KNOT_ENOMEM;
					}
				}
				// unmatching ACK is ignored, this includes:
				// - incoming out-of-order data
				// - ACK of some previous part of outgoing data
			} else {
				switch ((*conn)->state) {
				case XDP_TCP_NORMAL:
					break;
				case XDP_TCP_ESTABLISHING:
					(*conn)->state = XDP_TCP_NORMAL;
					break;
				case XDP_TCP_CLOSING:
					tcp_table_del(conn, tcp_table);
					break;
				}
			}
			break; // sole ACK without PSH is ignored
		case (KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK):
			if (!seq_ack_match) {
				resp_ack(msg, KNOT_XDP_MSG_RST);
			} else {
				if ((*conn)->state == XDP_TCP_CLOSING) {
					resp_ack(msg, KNOT_XDP_MSG_ACK);
					relay.action = XDP_TCP_CLOSE;
					if (knot_tcp_relay_dynarray_add(relays, &relay) == NULL) {
						ret = KNOT_ENOMEM;
					}
					tcp_table_del(conn, tcp_table);
				} else if (msg->payload.iov_len == 0) { // otherwise ignore FIN
					resp_ack(msg, KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK);
					relay.action = XDP_TCP_CLOSE;
					if (knot_tcp_relay_dynarray_add(relays, &relay) == NULL) {
						ret = KNOT_ENOMEM;
					}
					(*conn)->state = XDP_TCP_CLOSING;
					(*conn)->ackno++;
				}
			}
			break;
		case KNOT_XDP_MSG_RST:
			if (seq_ack_match) {
				relay.action = XDP_TCP_RESET;
				if (knot_tcp_relay_dynarray_add(relays, &relay) == NULL) {
					ret = KNOT_ENOMEM;
				}
				tcp_table_del(conn, tcp_table);
			}
			break;
		default:
			break;
		}
	}

	if (n_acks > 0 && ret == KNOT_EOK) {
		uint32_t sent_unused;
		(void)knot_xdp_send(socket, acks, n_acks, &sent_unused);
		(void)knot_xdp_send_finish(socket);
	}

#undef resp_ack

	return ret;
}

_public_
int knot_tcp_relay_answer(knot_tcp_relay_dynarray_t *relays, const knot_tcp_relay_t *relay,
                          void *data, size_t data_len)
{
	if (relays == NULL || relay == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	assert(data_len <= UINT16_MAX);
	uint16_t prefix = htobe16(data_len);
#define PREFIX_LEN (prefix == 0 ? 0 : sizeof(prefix))

	while (data_len > 0) {
		knot_tcp_relay_t *clone = knot_tcp_relay_dynarray_add(relays, relay);
		if (clone == NULL) {
			return KNOT_ENOMEM;
		}

		size_t chunk = MIN(data_len + PREFIX_LEN, relay->conn->mss);
		assert(chunk >= PREFIX_LEN);

		clone->data.iov_base = malloc(chunk);
		if (clone->data.iov_base == NULL) {
			return KNOT_ENOMEM;
		}
		clone->data.iov_len = chunk;

		memcpy(clone->data.iov_base, &prefix, PREFIX_LEN);
		chunk -= PREFIX_LEN;

		memcpy(clone->data.iov_base + PREFIX_LEN, data, chunk);
		clone->answer = XDP_TCP_ANSWER | XDP_TCP_DATA;
		clone->free_data = XDP_TCP_FREE_DATA;

		data += chunk;
		data_len -= chunk;
		prefix = 0;
	}
	return KNOT_EOK;
}

_public_
void knot_tcp_relay_free(knot_tcp_relay_dynarray_t *relays)
{
	if (relays == NULL) {
		return;
	}

	knot_dynarray_foreach(knot_tcp_relay, knot_tcp_relay_t, i, *relays) {
		if (i->free_data != XDP_TCP_FREE_NONE) {
			free(i->data.iov_base -
			     (i->free_data == XDP_TCP_FREE_PREFIX ? sizeof(uint16_t) : 0));
		}
	}
	knot_tcp_relay_dynarray_free(relays);
}

_public_
int knot_tcp_send(knot_xdp_socket_t *socket, knot_tcp_relay_t relays[], uint32_t relay_count)
{
	if (relay_count == 0) {
		return KNOT_EOK;
	}
	if (socket == NULL || relays == NULL) {
		return KNOT_EINVAL;
	}

	knot_xdp_msg_t msgs[relay_count], *msg = &msgs[0];
	int ret = KNOT_EOK, n_msgs = 0;

	for (size_t irl = 0; irl < relay_count; irl++) {
		knot_tcp_relay_t *rl = &relays[irl];
		if ((rl->answer & 0x0f) == XDP_TCP_NOOP) {
			continue;
		}

		knot_xdp_msg_flag_t fl = KNOT_XDP_MSG_TCP;
		if (rl->conn->ip_loc.sin6_family == AF_INET6) {
			fl |= KNOT_XDP_MSG_IPV6;
		}

		ret = knot_xdp_send_alloc(socket, fl, msg);
		if (ret != KNOT_EOK) {
			break;
		}

		memcpy( msg->eth_from, rl->conn->last_eth_loc, sizeof(msg->eth_from));
		memcpy( msg->eth_to,   rl->conn->last_eth_rem, sizeof(msg->eth_to));
		memcpy(&msg->ip_from, &rl->conn->ip_loc,  sizeof(msg->ip_from));
		memcpy(&msg->ip_to,   &rl->conn->ip_rem,  sizeof(msg->ip_to));

		msg->ackno = rl->conn->seqno;
		msg->seqno = rl->conn->ackno;

		switch (rl->answer & 0x0f) {
		case XDP_TCP_ESTABLISH:
			msg->flags |= KNOT_XDP_MSG_SYN;
			msg->payload.iov_len = 0;
			break;
		case XDP_TCP_DATA:
			msg->flags |= KNOT_XDP_MSG_ACK;
			if (rl->data.iov_len > UINT16_MAX ||
			    rl->data.iov_len > msg->payload.iov_len) {
				ret = KNOT_ESPACE;
			} else {
				memcpy(msg->payload.iov_base, rl->data.iov_base,
				       rl->data.iov_len);
				msg->payload.iov_len = rl->data.iov_len;
			}
			assert(rl->conn != NULL);
			rl->conn->ackno += msg->payload.iov_len;
			break;
		case XDP_TCP_CLOSE:
			msg->flags |= (KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK);
			msg->payload.iov_len = 0;
			assert(rl->conn != NULL);
			rl->conn->ackno++;
			rl->conn->state = XDP_TCP_CLOSING;
			break;
		case XDP_TCP_RESET:
		default:
			msg->flags |= KNOT_XDP_MSG_RST;
			msg->payload.iov_len = 0;
			break;
		}

		msg++;
		n_msgs++;
		if (ret != KNOT_EOK) {
			break;
		}
	}

	uint32_t sent_unused;
	(void)knot_xdp_send(socket, msgs, n_msgs, &sent_unused);

	return ret;
}

_public_
int knot_tcp_sweep(knot_tcp_table_t *tcp_table, knot_xdp_socket_t *socket,
                   uint32_t max_at_once, uint32_t close_timeout, uint32_t reset_timeout,
                   uint32_t reset_at_least, size_t reset_buf_size,
                   uint32_t *close_count, uint32_t *reset_count)
{
	if (tcp_table == NULL) {
		return KNOT_EINVAL;
	}

	knot_tcp_relay_t rl = { 0 };
	knot_tcp_relay_dynarray_t relays = { 0 };
	uint32_t now = get_timestamp(), i = 0;
	knot_tcp_conn_t *conn, *next;
	list_t to_remove;
	init_list(&to_remove);

	WALK_LIST_DELSAFE(conn, next, *tcp_table_timeout(tcp_table)) {
		if (i++ < reset_at_least ||
		    now - conn->last_active >= reset_timeout ||
		    (reset_buf_size > 0 && conn->inbuf.iov_len > 0)) {
			rl.answer = XDP_TCP_RESET;

			// move this conn into to-remove list
			rem_node((node_t *)conn);
			add_tail(&to_remove, (node_t *)conn);

			reset_buf_size -= MIN(reset_buf_size, conn->inbuf.iov_len);
		} else if (now - conn->last_active >= close_timeout) {
			if (conn->state != XDP_TCP_CLOSING) {
				rl.answer = XDP_TCP_CLOSE;
				if (close_count != NULL) {
					(*close_count)++;
				}
			}
		} else if (reset_buf_size == 0) {
			break;
		}

		rl.conn = conn;
		(void)knot_tcp_relay_dynarray_add(&relays, &rl);
		if (relays.size >= max_at_once) {
			break;
		}
	}

	knot_xdp_send_prepare(socket);
	(void)knot_tcp_send(socket, knot_tcp_relay_dynarray_arr(&relays), relays.size);
	(void)knot_xdp_send_finish(socket);

	// immediately remove reset connections
	if (reset_count != NULL) {
		*reset_count += list_size(&to_remove);
	}
	WALK_LIST_DELSAFE(conn, next, to_remove) {
		tcp_table_del_lookup(conn, tcp_table);
	}

	knot_tcp_relay_free(&relays);

	return KNOT_EOK;
}
