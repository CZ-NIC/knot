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

#include "libknot/xdp/tcp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libdnssec/random.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/xdp/tcp_iobuf.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/openbsd/siphash.h"

static uint32_t get_timestamp(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	uint64_t res = (uint64_t)t.tv_sec * 1000000;
	res += (uint64_t)t.tv_nsec / 1000;
	return res & 0xffffffff; // overflow does not matter since we are working with differences
}

static size_t sockaddr_data_len(const struct sockaddr_in6 *rem, const struct sockaddr_in6 *loc)
{
	assert(rem->sin6_family == loc->sin6_family);
	switch (rem->sin6_family) {
	case AF_INET:
		return offsetof(struct sockaddr_in, sin_zero);
	case AF_INET6:
		return sizeof(rem->sin6_family) + sizeof(rem->sin6_port) + sizeof(rem->sin6_flowinfo) + sizeof(rem->sin6_addr);
	default:
		return 0;
	}
}

static uint64_t hash_four_tuple(const struct sockaddr_in6 *rem, const struct sockaddr_in6 *loc,
                                uint32_t hash_secret[4])
{
	size_t socka_data_len = sockaddr_data_len(rem, loc);
	SIPHASH_KEY key;
	//assert(sizeof(key) == sizeof(hash_secret)); // beware, sizeof(hash_secret) == sizeof(uint32_t*)
	memcpy(&key, hash_secret, sizeof(key));
	SIPHASH_CTX ctx;
	SipHash24_Init(&ctx, &key);
	SipHash24_Update(&ctx, rem, socka_data_len);
	SipHash24_Update(&ctx, loc, socka_data_len);
	return SipHash24_End(&ctx);
}

_public_
knot_tcp_table_t *knot_tcp_table_new(size_t size)
{
	knot_tcp_table_t *t = calloc(1, sizeof(*t) + size * sizeof(t->conns[0]));
	if (t == NULL) {
		return t;
	}

	t->size = size;
	init_list(&t->timeout);

	for (size_t i = 0; i < sizeof(t->hash_secret) / sizeof(*t->hash_secret); i++) {
		t->hash_secret[i] = dnssec_random_uint32_t();
	}

	return t;
}

_public_
void knot_tcp_table_free(knot_tcp_table_t *t)
{
	if (t != NULL) {
		knot_tcp_conn_t *n, *next;
		WALK_LIST_DELSAFE(n, next, t->timeout) {
			free(n);
		}
		free(t);
	}
}

static knot_tcp_conn_t **tcp_table_lookup(const struct sockaddr_in6 *rem, const struct sockaddr_in6 *loc,
                                          uint64_t *hash, knot_tcp_table_t *table)
{
	*hash = hash_four_tuple(rem, loc, table->hash_secret);
	size_t sdl = sockaddr_data_len(rem, loc);
	knot_tcp_conn_t **res = table->conns + (*hash % table->size);
	while (*res != NULL) {
		if (memcmp(&(*res)->ip_rem, rem, sdl) == 0 &&
		    memcmp(&(*res)->ip_loc, loc, sdl) == 0) {
			rem_node(&(*res)->n);
			add_tail(&table->timeout, &(*res)->n);
			break;
		}
		res = &(*res)->next;
	}
	return res;
}

static void tcp_table_del(knot_tcp_conn_t **todel)
{
	knot_tcp_conn_t *conn = *todel;
	if (conn != NULL) {
		*todel = conn->next; // remove from conn-table linked list
		rem_node(&conn->n); // remove from timeout double-linked list
		free(conn->inbuf.iov_base);
		free(conn);
	}
}

static void tcp_table_del2(knot_tcp_conn_t **todel, knot_tcp_table_t *table)
{
	assert(table->usage > 0);
	tcp_table_del(todel);
	table->usage--;
}

static void tcp_table_del3(knot_tcp_conn_t *todel, knot_tcp_table_t *table)
{
	// re-lookup is needed to find the **pointer in the table
	uint64_t unused_hash;
	knot_tcp_conn_t **pconn = tcp_table_lookup(&todel->ip_rem, &todel->ip_loc, &unused_hash, table);
	assert(*pconn == todel);
	tcp_table_del2(pconn, table);
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
	add_tail(&table->timeout, &c->n);

	c->state = XDP_TCP_NORMAL;
	memset(&c->inbuf, 0, sizeof(c->inbuf));

	c->next = *addto;
	*addto = c;

	table->usage++;
	*res = c;
	return KNOT_EOK;
}

dynarray_define(tcp_relay, knot_tcp_relay_t, DYNARRAY_VISIBILITY_PUBLIC)

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
int knot_xdp_tcp_relay(knot_xdp_socket_t *socket, knot_xdp_msg_t msgs[], uint32_t msg_count,
                       knot_tcp_table_t *tcp_table, knot_tcp_table_t *syn_table,
                       tcp_relay_dynarray_t *relays, knot_mm_t *mm)
{
	if (msg_count == 0) {
		return KNOT_EOK;
	}
	if (socket == NULL || msgs == NULL || relays == NULL) {
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
		knot_tcp_conn_t **conn = tcp_table_lookup(&msg->ip_from, &msg->ip_to, &conn_hash, tcp_table);
		bool seq_ack_match = check_seq_ack(msg, *conn);
		if (seq_ack_match) {
			(*conn)->seqno = knot_tcp_next_seqno(msg);
			memcpy((*conn)->last_eth_rem, msg->eth_from, sizeof((*conn)->last_eth_rem));
			memcpy((*conn)->last_eth_loc, msg->eth_to, sizeof((*conn)->last_eth_loc));
			(*conn)->last_active = get_timestamp();
			if (msg->flags & KNOT_XDP_MSG_ACK) {
				(*conn)->acked = msg->ackno;
			}
		}

		knot_tcp_relay_t relay = { .msg = msg, .conn = *conn };

		switch (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK |
		                      KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_RST)) {
		case KNOT_XDP_MSG_SYN:
		case (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK):
			if (*conn == NULL) {
				bool synack = (msg->flags & KNOT_XDP_MSG_ACK);
				resp_ack(msg, synack ? KNOT_XDP_MSG_ACK : (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK));
				relay.action = synack ? XDP_TCP_ESTABLISH : XDP_TCP_SYN;
				ret = tcp_table_add(msg, conn_hash, (syn_table == NULL || synack) ? tcp_table : syn_table, &relay.conn);
				tcp_relay_dynarray_add(relays, &relay);
				relay.conn->state = XDP_TCP_ESTABLISHING;
				relay.conn->seqno++;
				if (!synack) {
					relay.conn->acked = acks[n_acks - 1].seqno;
					relay.conn->ackno = relay.conn->acked + 1;
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
					tcp_table_del2(conn, syn_table);
					*conn = NULL;
					relay.action = XDP_TCP_ESTABLISH;
					ret = tcp_table_add(msg, conn_hash, tcp_table, &relay.conn);
					tcp_relay_dynarray_add(relays, &relay);
				}
				// unmatching ACK is ignored, this includes:
				// - incomming out-of-order data
				// - ACK of some previous part of outgoing data
			} else if (msg->payload.iov_len > 0) {
				resp_ack(msg, KNOT_XDP_MSG_ACK);
				relay.action = XDP_TCP_DATA;

				struct iovec msg_payload = msg->payload, tofree;
				ret = knot_tcp_input_buffers(&(*conn)->inbuf, &msg_payload, &tofree);

				if (tofree.iov_len > 0 && ret == KNOT_EOK) {
					FILE *f = fopen("/tmp/ddns.bin", "w");
					fwrite(tofree.iov_base, tofree.iov_len, 1, f);
					fclose(f);

					relay.data.iov_base = tofree.iov_base + sizeof(uint16_t);
					relay.data.iov_len = tofree.iov_len - sizeof(uint16_t);
					relay.free_data = XDP_TCP_FREE_PREFIX;
					tcp_relay_dynarray_add(relays, &relay);
					relay.free_data = XDP_TCP_FREE_NONE;
				}
				while (msg_payload.iov_len > 0 && ret == KNOT_EOK) {
					size_t dns_len = knot_tcp_pay_len(&msg_payload);
					assert(dns_len >= msg_payload.iov_len);
					relay.data.iov_base = msg_payload.iov_base + sizeof(uint16_t);
					relay.data.iov_len = dns_len - sizeof(uint16_t);
					tcp_relay_dynarray_add(relays, &relay);

					msg_payload.iov_base += dns_len;
					msg_payload.iov_len -= dns_len;
				}
			} else {
				switch ((*conn)->state) {
				case XDP_TCP_NORMAL:
					break;
				case XDP_TCP_ESTABLISHING:
					(*conn)->state = XDP_TCP_NORMAL;
					break;
				case XDP_TCP_CLOSING:
					tcp_table_del2(conn, tcp_table);
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
					tcp_relay_dynarray_add(relays, &relay);
					tcp_table_del2(conn, tcp_table);
				} else {
					resp_ack(msg, KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK);
					relay.action = XDP_TCP_CLOSE;
					tcp_relay_dynarray_add(relays, &relay);
					(*conn)->state = XDP_TCP_CLOSING;
					(*conn)->ackno++;
				}
			}
			break;
		case KNOT_XDP_MSG_RST:
			if (seq_ack_match) {
				relay.action = XDP_TCP_RESET;
				tcp_relay_dynarray_add(relays, &relay);
				tcp_table_del2(conn, tcp_table);
			}
			break;
		default:
			break;
		}
	}

	if (n_acks > 0 && ret == KNOT_EOK) {
		uint32_t sent_unused;
		ret = knot_xdp_send(socket, acks, n_acks, &sent_unused);
		if (ret == KNOT_EOK) {
			ret = knot_xdp_send_finish(socket);
		}
	}

	return ret;
}

_public_
void knot_xdp_tcp_relay_free(tcp_relay_dynarray_t *relays)
{
	dynarray_foreach(tcp_relay, knot_tcp_relay_t, i, *relays) {
		if (i->free_data != XDP_TCP_FREE_NONE) {
			free(i->data.iov_base - (i->free_data == XDP_TCP_FREE_PREFIX ? sizeof(uint16_t) : 0));
		}
	}
	tcp_relay_dynarray_free(relays);
}

_public_
int knot_xdp_tcp_send(knot_xdp_socket_t *socket, knot_tcp_relay_t relays[],
                      uint32_t relay_count)
{
	if (relay_count == 0) {
		return KNOT_EOK;
	}
	if (socket == NULL || relays == NULL) {
		return KNOT_EINVAL;
	}

	knot_xdp_msg_t msgs[relay_count], *msg = &msgs[0];
	int ret = KNOT_EOK, n_msgs = 0;

	knot_xdp_send_prepare(socket);

	for (size_t irl = 0; irl < relay_count; irl++) {
		knot_tcp_relay_t *rl = &relays[irl];
		if ((rl->answer & 0x0f) == XDP_TCP_NOOP) {
			continue;
		}

		if (rl->answer & XDP_TCP_ANSWER) {
			ret = knot_xdp_reply_alloc(socket, rl->msg, msg);
			if (ret != KNOT_EOK) {
				break;
			}
		} else {
			ret = knot_xdp_send_alloc(socket, KNOT_XDP_MSG_TCP, msg);
			if (ret != KNOT_EOK) {
				break;
			}

			memcpy( msg->eth_from, rl->conn->last_eth_loc, sizeof(msg->eth_from));
			memcpy( msg->eth_to,   rl->conn->last_eth_rem, sizeof(msg->eth_to));
			memcpy(&msg->ip_from, &rl->conn->ip_loc,  sizeof(msg->ip_from));
			memcpy(&msg->ip_to,   &rl->conn->ip_rem,  sizeof(msg->ip_to));

			if (rl->conn->ip_loc.sin6_family == AF_INET6) {
				msg->flags |= KNOT_XDP_MSG_IPV6;
			}
			msg->ackno = rl->conn->seqno;
			msg->seqno = rl->conn->ackno;
		}

		switch (rl->answer & 0x0f) {
		case XDP_TCP_ESTABLISH:
			msg->flags |= KNOT_XDP_MSG_SYN;
			msg->payload.iov_len = 0;
			break;
		case XDP_TCP_DATA:
			msg->flags |= KNOT_XDP_MSG_ACK;
			if (rl->data.iov_len > UINT16_MAX ||
			    rl->data.iov_len > msg->payload.iov_len - sizeof(uint16_t)) {
				ret = KNOT_ESPACE;
			} else {
				*(uint16_t *)msg->payload.iov_base = htobe16(rl->data.iov_len);
				memcpy(msg->payload.iov_base + sizeof(uint16_t), rl->data.iov_base, rl->data.iov_len);
				msg->payload.iov_len = rl->data.iov_len + sizeof(uint16_t);
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
	if (ret == KNOT_EOK) {
		ret = knot_xdp_send(socket, msgs, n_msgs, &sent_unused);
	} else {
		knot_xdp_send_free(socket, msgs, n_msgs);
	}
	if (ret == KNOT_EOK) {
		ret = knot_xdp_send_finish(socket);
		if (ret == KNOT_EAGAIN) {
			ret = KNOT_EOK;
		}
	}
	return ret;
}

_public_
int knot_xdp_tcp_timeout(knot_tcp_table_t *tcp_table, knot_xdp_socket_t *socket,
                         uint32_t max_at_once,
                         uint32_t close_timeout, uint32_t reset_timeout,
                         uint32_t reset_at_least, size_t reset_inbufs,
                         uint32_t *reset_count)
{
	knot_tcp_relay_t rl = { 0 };
	tcp_relay_dynarray_t relays = { 0 };
	uint32_t now = get_timestamp(), i = 0;
	knot_tcp_conn_t *conn, *next;
	int ret = KNOT_EOK;
	list_t to_remove;
	init_list(&to_remove);

	WALK_LIST_DELSAFE(conn, next, tcp_table->timeout) {
		if (i++ < reset_at_least ||
		    now - conn->last_active >= reset_timeout ||
		    (reset_inbufs > 0 && conn->inbuf.iov_len > 0)) {
			rl.answer = XDP_TCP_RESET;
			printf("reset %hu%s%s%s\n", be16toh(conn->ip_rem.sin6_port), i - 1 < reset_at_least ? " table full" : "", now - conn->last_active >= reset_timeout ? " too old" : "", (reset_inbufs > 0 && conn->inbuf.iov_len > 0) ? " inbuf usage" : "");

			// move this conn into to-remove list
			rem_node((node_t *)conn);
			add_tail(&to_remove, (node_t *)conn);

			reset_inbufs -= MIN(reset_inbufs, conn->inbuf.iov_len);
		} else if (now - conn->last_active >= close_timeout) {
			if (conn->state != XDP_TCP_CLOSING) {
				rl.answer = XDP_TCP_CLOSE;
				printf("close %hu timeout\n", be16toh(conn->ip_rem.sin6_port));
			}
		} else if (reset_inbufs == 0) {
			break;
		}

		rl.conn = conn;
		tcp_relay_dynarray_add(&relays, &rl);
		if (relays.size >= max_at_once) {
			break;
		}
	}

	if (ret == KNOT_EOK) {
		ret = knot_xdp_tcp_send(socket, tcp_relay_dynarray_arr(&relays), relays.size);
	}

	// immediately remove resetted connections
	if (ret == KNOT_EOK) {
		if (reset_count != NULL) {
			*reset_count = list_size(&to_remove);
		}
		WALK_LIST_DELSAFE(conn, next, to_remove) {
			tcp_table_del3(conn, tcp_table);
		}
	}

	knot_xdp_tcp_relay_free(&relays);
	return ret;
}

_public_
void knot_xdp_tcp_cleanup(knot_tcp_table_t *tcp_table, uint32_t timeout,
                          uint32_t at_least, uint32_t *cleaned)
{
	uint32_t now = get_timestamp(), i = 0;
	knot_tcp_conn_t *conn, *next;
	WALK_LIST_DELSAFE(conn, next, tcp_table->timeout) {
		if (i++ < at_least || now - conn->last_active >= timeout) {
			tcp_table_del3(conn, tcp_table);
			if (cleaned != NULL) {
				(*cleaned)++;
			}
		}
	}
}
