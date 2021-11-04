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
#include "libknot/xdp/tcp_iobuf.h"
#include "libknot/attribute.h"
#include "libknot/error.h"
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
knot_tcp_table_t *knot_tcp_table_new(size_t size, knot_tcp_table_t *secret_share)
{
	knot_tcp_table_t *table = calloc(1, sizeof(*table) + sizeof(list_t) +
	                                    size * sizeof(table->conns[0]));
	if (table == NULL) {
		return table;
	}

	table->size = size;
	init_list(tcp_table_timeout(table));

	assert(sizeof(table->hash_secret) == sizeof(SIPHASH_KEY));
	if (secret_share == NULL) {
		table->hash_secret[0] = dnssec_random_uint64_t();
		table->hash_secret[1] = dnssec_random_uint64_t();
	} else {
		table->hash_secret[0] = secret_share->hash_secret[0];
		table->hash_secret[1] = secret_share->hash_secret[1];
	}

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
			break;
		}
		res = &(*res)->next;
	}
	return res;
}

static knot_tcp_conn_t **tcp_table_re_lookup(knot_tcp_conn_t *conn,
                                             knot_tcp_table_t *table)
{
	uint64_t unused_hash;
	knot_tcp_conn_t **res = tcp_table_lookup(&conn->ip_rem, &conn->ip_loc,
	                                         &unused_hash, table);
	assert(*res == conn);
	return res;
}

static void del_conn(knot_tcp_conn_t *conn)
{
	if (conn != NULL) {
		free(conn->inbuf.iov_base);
		free(conn->outbufs.bufs);
		free(conn);
	}
}

static void tcp_table_remove_conn(knot_tcp_conn_t **todel)
{
	rem_node(tcp_conn_node(*todel)); // remove from timeout double-linked list
	*todel = (*todel)->next; // remove from conn-table linked list
}

static void tcp_table_del_conn(knot_tcp_conn_t **todel)
{
	knot_tcp_conn_t *conn = *todel;
	tcp_table_remove_conn(todel);
	del_conn(conn);
}

static void tcp_table_remove(knot_tcp_conn_t **todel, knot_tcp_table_t *table)
{
	assert(table->usage > 0);
	table->inbufs_total -= (*todel)->inbuf.iov_len;
	tcp_table_remove_conn(todel);
	table->usage--;
}

static void tcp_table_del(knot_tcp_conn_t **todel, knot_tcp_table_t *table)
{
	assert(table->usage > 0);
	table->inbufs_total -= (*todel)->inbuf.iov_len;
	tcp_table_del_conn(todel);
	table->usage--;
}

static void conn_init_from_msg(knot_tcp_conn_t *conn, knot_xdp_msg_t *msg)
{
	memcpy(&conn->ip_rem, &msg->ip_from, sizeof(conn->ip_rem));
	memcpy(&conn->ip_loc, &msg->ip_to,   sizeof(conn->ip_loc));

	memcpy(&conn->last_eth_rem, &msg->eth_from, sizeof(conn->last_eth_rem));
	memcpy(&conn->last_eth_loc, &msg->eth_to,   sizeof(conn->last_eth_loc));

	conn->seqno = msg->seqno;
	conn->ackno = msg->ackno;
	conn->acked = msg->ackno;

	conn->last_active = get_timestamp();
	conn->state = XDP_TCP_NORMAL;
	conn->establish_rtt = 0;

	memset(&conn->inbuf, 0, sizeof(conn->inbuf));
	memset(&conn->outbufs, 0, sizeof(conn->outbufs));
}

static void tcp_table_insert(knot_tcp_conn_t *conn, uint64_t hash,
                             knot_tcp_table_t *table)
{
	knot_tcp_conn_t **addto = table->conns + (hash % table->size);
	add_tail(tcp_table_timeout(table), tcp_conn_node(conn));
	conn->next = *addto;
	*addto = conn;
	table->usage++;
}

// WARNING you shall ensure that it's not in the table already!
static int tcp_table_add(knot_xdp_msg_t *msg, uint64_t hash, knot_tcp_table_t *table,
                         knot_tcp_conn_t **res)
{
	knot_tcp_conn_t *c = malloc(sizeof(*c));
	if (c == NULL) {
		return KNOT_ENOMEM;
	}
	conn_init_from_msg(c, msg);
	tcp_table_insert(c, hash, table);
	*res = c;
	return KNOT_EOK;
}

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
int knot_tcp_recv(knot_tcp_relay_t *relays, knot_xdp_msg_t *msgs, uint32_t count,
                  knot_tcp_table_t *tcp_table, knot_tcp_table_t *syn_table)
{
	if (count == 0) {
		return KNOT_EOK;
	}
	if (relays == NULL || msgs == NULL || tcp_table == NULL) {
		return KNOT_EINVAL;
	}
	memset(relays, 0, count * sizeof(*relays));

	knot_tcp_relay_t *relay = relays;
	int ret = KNOT_EOK;

	for (knot_xdp_msg_t *msg = msgs; msg != msgs + count && ret == KNOT_EOK; msg++) {
		if (!(msg->flags & KNOT_XDP_MSG_TCP)) {
			continue;
		}

		uint64_t conn_hash;
		knot_tcp_conn_t **pconn = tcp_table_lookup(&msg->ip_from, &msg->ip_to,
		                                           &conn_hash, tcp_table);
		knot_tcp_conn_t *conn = *pconn;
		bool seq_ack_match = check_seq_ack(msg, conn);
		if (seq_ack_match) {
			assert(conn->mss != 0);
			conn->seqno = knot_tcp_next_seqno(msg);
			memcpy(conn->last_eth_rem, msg->eth_from, sizeof(conn->last_eth_rem));
			memcpy(conn->last_eth_loc, msg->eth_to, sizeof(conn->last_eth_loc));
			conn->window_size = (uint32_t)msg->win * (1LU << conn->window_scale);

			uint32_t now = get_timestamp();
			if (conn->establish_rtt == 0 && conn->last_active != 0) {
				conn->establish_rtt = now - conn->last_active;
			}
			conn->last_active = now;

			rem_node(tcp_conn_node(conn));
			add_tail(tcp_table_timeout(tcp_table), tcp_conn_node(conn));

			if (msg->flags & KNOT_XDP_MSG_ACK) {
				conn->acked = msg->ackno;
				tcp_outbufs_ack(&conn->outbufs, msg->ackno, &tcp_table->outbufs_total);
			}
		}

		relay->msg = msg;
		relay->conn = conn;

		// process incoming data
		if (seq_ack_match && (msg->flags & KNOT_XDP_MSG_ACK) && msg->payload.iov_len > 0) {
			relay->auto_answer = KNOT_XDP_MSG_ACK;
			ret = tcp_inbuf_update(&conn->inbuf, msg->payload, &relay->inbufs,
			                       &relay->inbufs_count, &tcp_table->inbufs_total);
			if (ret != KNOT_EOK) {
				break;
			}
		}

		// process TCP connection state
		switch (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK |
		                      KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_RST)) {
		case KNOT_XDP_MSG_SYN:
		case (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK):
			if (conn == NULL) {
				bool synack = (msg->flags & KNOT_XDP_MSG_ACK);

				ret = tcp_table_add(msg, conn_hash,
				                    (syn_table == NULL || synack) ? tcp_table : syn_table,
				                    &relay->conn);
				if (ret == KNOT_EOK) {
					relay->action = synack ? XDP_TCP_ESTABLISH : XDP_TCP_SYN;
					relay->auto_answer = synack ? KNOT_XDP_MSG_ACK : (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK);

					conn = relay->conn;
					conn->state = XDP_TCP_ESTABLISHING;
					conn->seqno++;
					conn->mss = MAX(msg->mss, 536); // minimal MSS, most importantly not zero!
					conn->window_scale = msg->win_scale;
					if (!synack) {
						conn->acked = dnssec_random_uint32_t();
						conn->ackno = conn->acked;
					}
				}
			} else {
				relay->auto_answer = KNOT_XDP_MSG_ACK;
			}
			break;
		case KNOT_XDP_MSG_ACK:
			if (!seq_ack_match) {
				uint64_t syn_hash;
				if (syn_table != NULL && msg->payload.iov_len == 0 &&
				    (pconn = tcp_table_lookup(&msg->ip_from, &msg->ip_to, &syn_hash, syn_table)) != NULL &&
				    (conn = *pconn) != NULL && check_seq_ack(msg, conn)) {
					// move conn from syn_table to tcp_table
					tcp_table_remove(pconn, syn_table);
					tcp_table_insert(conn, conn_hash, tcp_table);
					relay->conn = conn;
					relay->action = XDP_TCP_ESTABLISH;
					conn->state = XDP_TCP_NORMAL;
				}
			} else {
				switch (conn->state) {
				case XDP_TCP_NORMAL:
				case XDP_TCP_CLOSING1: // just a mess, ignore
					break;
				case XDP_TCP_ESTABLISHING:
					conn->state = XDP_TCP_NORMAL;
					relay->action = XDP_TCP_ESTABLISH;
					break;
				case XDP_TCP_CLOSING2:
					tcp_table_del(pconn, tcp_table);
					relay->conn = NULL;
					break;
				}
			}
			break;
		case (KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK):
			if (!seq_ack_match) {
				if (conn != NULL) {
					relay->auto_answer = KNOT_XDP_MSG_RST;
					relay->auto_seqno = msg->ackno;
				} // else ignore. It would be better and possible, but no big value for the price of CPU.
			} else {
				if (conn->state == XDP_TCP_CLOSING1) {
					relay->action = XDP_TCP_CLOSE;
					relay->auto_answer = KNOT_XDP_MSG_ACK;
					relay->answer = XDP_TCP_FREE;
					tcp_table_remove(pconn, tcp_table);
				} else if (msg->payload.iov_len == 0) { // otherwise ignore FIN
					relay->action = XDP_TCP_CLOSE;
					relay->auto_answer = KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK;
					conn->state = XDP_TCP_CLOSING2;
				}
			}
			break;
		case KNOT_XDP_MSG_RST:
			if (conn != NULL && msg->seqno == conn->seqno) {
				relay->action = XDP_TCP_RESET;
				tcp_table_del(pconn, tcp_table);
				relay->conn = NULL;
			} else if (conn != NULL) {
				relay->auto_answer = KNOT_XDP_MSG_ACK;
			}
			break;
		default:
			break;
		}

		if (!knot_tcp_relay_empty(relay)) {
			relay++;
		}
	}

	return ret;
}

_public_
int knot_tcp_reply_data(knot_tcp_relay_t *relay, knot_tcp_table_t *tcp_table,
                        uint8_t *data, size_t len)
{
	if (relay == NULL || tcp_table == NULL || relay->conn == NULL) {
		return KNOT_EINVAL;
	}
	return tcp_outbufs_add(&relay->conn->outbufs, data, len,
	                       relay->conn->mss, &tcp_table->outbufs_total);
}

static knot_xdp_msg_t *first_msg(knot_xdp_msg_t *msgs, uint32_t n_msgs)
{
	memset(msgs, 0, n_msgs * sizeof(*msgs));
	return msgs - 1; // will be incremented just before first use
}

static int send_msgs(knot_xdp_msg_t *msgs, uint32_t n_msgs, knot_xdp_socket_t *socket)
{
	uint32_t sent = 0;
	if (n_msgs == 0) {
		return KNOT_EOK;
	}

	int ret = knot_xdp_send(socket, msgs, n_msgs, &sent);
	if (ret != KNOT_EOK) {
		printf("TCP send[%u/%u]: %s\n", sent, n_msgs, knot_strerror(ret));
	}
	return KNOT_EOK; // ignore errcode from send
}

static void msg_init_from_conn(knot_xdp_msg_t *msg, knot_tcp_conn_t *conn)
{
	memcpy( msg->eth_from, conn->last_eth_loc, sizeof(msg->eth_from));
	memcpy( msg->eth_to,   conn->last_eth_rem, sizeof(msg->eth_to));
	memcpy(&msg->ip_from, &conn->ip_loc,  sizeof(msg->ip_from));
	memcpy(&msg->ip_to,   &conn->ip_rem,  sizeof(msg->ip_to));

	msg->ackno = conn->seqno;
	msg->seqno = conn->ackno;

	msg->payload.iov_len = 0;

	msg->win_scale = 14; // maximum possible
	msg->win = 0xffff;
}

static int next_msg(knot_xdp_msg_t *msgs, uint32_t n_msgs, knot_xdp_msg_t **cur,
                     knot_xdp_socket_t *socket, knot_tcp_relay_t *rl)
{
	(*cur)++;
	if (*cur - msgs >= n_msgs) {
		(void)send_msgs(msgs, n_msgs, socket);
		*cur = first_msg(msgs, n_msgs);
		(*cur)++;
	}

	knot_xdp_msg_t *msg = *cur;

	knot_xdp_msg_flag_t fl = KNOT_XDP_MSG_TCP;
	if (rl->conn->ip_loc.sin6_family == AF_INET6) {
		fl |= KNOT_XDP_MSG_IPV6;
	}
	if (rl->conn->state == XDP_TCP_ESTABLISHING) {
		fl |= KNOT_XDP_MSG_MSS | KNOT_XDP_MSG_WSC;
	}

	int ret = knot_xdp_send_alloc(socket, fl, msg);
	if (ret != KNOT_EOK) {
		return ret;
	}

	msg_init_from_conn(msg, rl->conn);

	return ret;
}

_public_
int knot_tcp_send(knot_xdp_socket_t *socket, knot_tcp_relay_t relays[], uint32_t relay_count,
                  uint32_t max_at_once)
{
	if (relay_count == 0) {
		return KNOT_EOK;
	}
	if (socket == NULL || relays == NULL) {
		return KNOT_EINVAL;
	}

	knot_xdp_send_prepare(socket);

	knot_xdp_msg_t msgs[max_at_once], *first = first_msg(msgs, max_at_once), *msg = first;
	int ret = KNOT_EOK;

	for (uint32_t i = 0; i < relay_count; i++) {
		knot_tcp_relay_t *rl = &relays[i];

#define NEXT_MSG if ((ret = next_msg(msgs, max_at_once, &msg, socket, rl)) != KNOT_EOK) { return ret; }

		if (rl->auto_answer != 0) {
			NEXT_MSG
			msg->flags |= rl->auto_answer;
			if (msg->flags & (KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_FIN)) {
				rl->conn->ackno++;
			}
			if (rl->auto_answer == KNOT_XDP_MSG_RST) {
				msg->seqno = rl->auto_seqno;
			}
		}

		switch (rl->answer & 0x0f) {
		case XDP_TCP_ESTABLISH:
			NEXT_MSG
			msg->flags |= KNOT_XDP_MSG_SYN;
			rl->conn->ackno++;
			break;
		case XDP_TCP_CLOSE:
			NEXT_MSG
			msg->flags |= (KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK);
			rl->conn->ackno++;
			rl->conn->state = XDP_TCP_CLOSING1;
			break;
		case XDP_TCP_RESET:
			NEXT_MSG
			msg->flags |= KNOT_XDP_MSG_RST;
			break;
		case XDP_TCP_NOOP:
		default:
			break;
		}

		size_t can_data = 0;
		struct tcp_outbuf *ob;
		if (rl->conn != NULL) {
			tcp_outbufs_can_send(&rl->conn->outbufs, rl->conn->window_size,
			                     rl->answer == XDP_TCP_RESEND, &ob, &can_data);
		}
		while (can_data > 0) {
			NEXT_MSG
			msg->flags |= KNOT_XDP_MSG_ACK;
			msg->payload.iov_len = ob->len;
			memcpy(msg->payload.iov_base, ob->bytes, ob->len);

			if (!ob->sent) {
				assert(rl->conn->ackno == msg->seqno);
				rl->conn->ackno += msg->payload.iov_len;
			} else {
				msg->seqno = ob->seqno;
			}

			ob->sent = true;
			ob->seqno = msg->seqno;

			can_data--;
			ob = ob->next;
		}
	}

#undef NEXT_MSG

	ret = send_msgs(msgs, msg - first, socket);
	(void)knot_xdp_send_finish(socket);

	return ret;
}

_public_
int knot_tcp_sweep(knot_tcp_table_t *tcp_table,
                   uint32_t close_timeout, uint32_t reset_timeout,
                   uint32_t resend_timeout, uint32_t limit_n_conn,
                   size_t limit_ibuf_size, size_t limit_obuf_size,
                   knot_tcp_relay_t *relays, size_t max_relays,
                   uint32_t *close_count, uint32_t *reset_count)
{
	if (tcp_table == NULL || relays == NULL || max_relays < 1) {
		return KNOT_EINVAL;
	}

	uint32_t now = get_timestamp(), i = 0;
	memset(relays, 0, max_relays * sizeof(*relays));
	knot_tcp_relay_t *rl = relays;

	ssize_t free_conns =  (ssize_t)tcp_table->usage - limit_n_conn;
	ssize_t free_inbuf =  (ssize_t)tcp_table->inbufs_total - limit_ibuf_size;
	ssize_t free_outbuf = (ssize_t)tcp_table->outbufs_total - limit_obuf_size;

	knot_tcp_conn_t *conn, *next;
	WALK_LIST_DELSAFE(conn, next, *tcp_table_timeout(tcp_table)) {
		rl->conn = conn;

		if (i++ < free_conns ||
		    now - conn->last_active >= reset_timeout ||
		    (free_inbuf > 0 && conn->inbuf.iov_len > 0) ||
		    (free_outbuf > 0 && tcp_outbufs_usage(&conn->outbufs) > 0)) {
			rl->answer = XDP_TCP_RESET | XDP_TCP_FREE;
			tcp_table_remove(tcp_table_re_lookup(conn, tcp_table), tcp_table);

			free_inbuf -= conn->inbuf.iov_len;
			free_outbuf -= tcp_outbufs_usage(&conn->outbufs);

			if (reset_count != NULL) {
				(*reset_count)++;
			}
		} else if (now - conn->last_active >= close_timeout) {
			if (conn->state != XDP_TCP_CLOSING1) {
				rl->answer = XDP_TCP_CLOSE;
				if (close_count != NULL) {
					(*close_count)++;
				}
			}
		} else if (now - conn->last_active >= resend_timeout &&
		           conn->outbufs.bufs != NULL && conn->outbufs.bufs->sent) {
			rl->answer = XDP_TCP_RESEND;
		}

		if (rl->answer != XDP_TCP_NOOP) {
			if (++rl == relays + max_relays) {
				break;
			}
		}
	}
	return KNOT_EOK;
}

_public_
void knot_tcp_cleanup(knot_tcp_table_t *tcp_table, knot_tcp_relay_t *relays, size_t n_relays)
{
	(void)tcp_table;
	for (uint32_t i = 0; i < n_relays; i++) {
		if (relays[i].answer & XDP_TCP_FREE) {
			del_conn(relays[i].conn);
		}
		free(relays[i].inbufs);
	}
}
