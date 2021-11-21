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

#include <unistd.h>

#include "tap/basic.h"
#include "libknot/error.h"
#include "libknot/xdp/msg_init.h"
#include "libknot/xdp/tcp.c"
#include "libknot/xdp/tcp_iobuf.c"
#include "libknot/xdp/bpf-user.h"

knot_tcp_table_t *test_table = NULL;
#define TEST_TABLE_SIZE 100

size_t sent_acks = 0;
size_t sent_rsts = 0;
size_t sent_syns = 0;
size_t sent_fins = 0;
uint32_t sent_seqno = 0;
uint32_t sent_ackno = 0;

knot_xdp_socket_t *test_sock = NULL;

struct sockaddr_in test_addr = { AF_INET, 0, { 127 + (1 << 24) }, { 0 } };

knot_tcp_conn_t *test_conn = NULL;

/*!
 * \brief Length of timeout-watching list.
 */
static size_t tcp_table_timeout_length(knot_tcp_table_t *table)
{
	return list_size(tcp_table_timeout(table));
}

/*!
 * \brief Clean up old TCP connection w/o sending RST or FIN.
 *
 * \param tcp_table     TCP connection table to clean up.
 * \param timeout       Remove connections older than this (usecs).
 * \param at_least      Remove at least this number of connections.
 * \param cleaned       Optional: Out: number of removed connections.
 */
static void tcp_cleanup(knot_tcp_table_t *tcp_table, uint32_t timeout,
                        uint32_t at_least, uint32_t *cleaned)
{
	uint32_t now = get_timestamp(), i = 0;
	knot_tcp_conn_t *conn, *next;
	WALK_LIST_DELSAFE(conn, next, *tcp_table_timeout(tcp_table)) {
		if (i++ < at_least || now - conn->last_active >= timeout) {
			tcp_table_del_lookup(conn, tcp_table);
			if (cleaned != NULL) {
				(*cleaned)++;
			}
		}
	}
}

/*!
 * \brief Find connection related to incoming message.
 */
static knot_tcp_conn_t *tcp_table_find(knot_tcp_table_t *table, knot_xdp_msg_t *msg_recv)
{
	uint64_t unused;
	return *tcp_table_lookup(&msg_recv->ip_from, &msg_recv->ip_to, &unused, table);
}

static int mock_send(_unused_ knot_xdp_socket_t *sock, const knot_xdp_msg_t msgs[],
                     uint32_t n_msgs, _unused_ uint32_t *sent)
{
	ok(n_msgs <= 20, "send: not too many at once");
	for (uint32_t i = 0; i < n_msgs; i++) {
		const knot_xdp_msg_t *msg = msgs + i;

		ok(msg->flags & KNOT_XDP_MSG_TCP, "send: is TCP message");
		ok(msg->payload.iov_len == 0, "send: is empty payload");

		if (msg->flags & KNOT_XDP_MSG_RST) {
			ok(!(msg->flags & KNOT_XDP_MSG_ACK), "send: no RST+ACK");
			sent_rsts++;
		} else if (msg->flags & KNOT_XDP_MSG_SYN) {
			ok(msg->flags & KNOT_XDP_MSG_ACK, "send: is SYN+ACK");
			sent_syns++;
		} else if (msg->flags & KNOT_XDP_MSG_FIN) {
			ok(msg->flags & KNOT_XDP_MSG_ACK, "send: FIN has always ACK");
			sent_fins++;
		} else {
			ok(msg->flags & KNOT_XDP_MSG_ACK, "send: is ACK");
			sent_acks++;
		}

		sent_seqno = msg->seqno;
		sent_ackno = msg->ackno;
	}
	return KNOT_EOK;
}

static int mock_send_nocheck(_unused_ knot_xdp_socket_t *sock, const knot_xdp_msg_t msgs[],
                             uint32_t n_msgs, _unused_ uint32_t *sent)
{
	for (uint32_t i = 0; i < n_msgs; i++) {
		const knot_xdp_msg_t *msg = msgs + i;
		if (msg->flags & KNOT_XDP_MSG_RST) {
			sent_rsts++;
		} else if (msg->flags & KNOT_XDP_MSG_SYN) {
			sent_syns++;
		} else if (msg->flags & KNOT_XDP_MSG_FIN) {
			sent_fins++;
		} else {
			sent_acks++;
		}
		sent_seqno = msg->seqno;
		sent_ackno = msg->ackno;
	}
	return KNOT_EOK;
}

static void clean_table(void)
{
	(void)tcp_cleanup(test_table, 0, UINT32_MAX, NULL);
}

static void clean_sent(void)
{
	sent_acks = 0;
	sent_rsts = 0;
	sent_syns = 0;
	sent_fins = 0;
}

static void check_sent(size_t expect_acks, size_t expect_rsts, size_t expect_syns, size_t expect_fins)
{
	is_int(expect_acks, sent_acks, "sent ACKs");
	is_int(expect_rsts, sent_rsts, "sent RSTs");
	is_int(expect_syns, sent_syns, "sent SYNs");
	is_int(expect_fins, sent_fins, "sent FINs");
	clean_sent();
}

static void prepare_msg(knot_xdp_msg_t *msg, int flags, uint16_t sport, uint16_t dport)
{
	msg_init(msg, flags | KNOT_XDP_MSG_TCP);
	memcpy(&msg->ip_from, &test_addr, sizeof(test_addr));
	memcpy(&msg->ip_to, &test_addr, sizeof(test_addr));
	msg->ip_from.sin6_port = htobe16(sport);
	msg->ip_to.sin6_port = htobe16(dport);
}

static void prepare_seqack(knot_xdp_msg_t *msg, int seq_shift, int ack_shift)
{
	msg->seqno = sent_ackno + seq_shift;
	msg->ackno = sent_seqno + ack_shift;
}

static void prepare_data(knot_xdp_msg_t *msg, const char *bytes, size_t n)
{
	msg->payload.iov_len = n;
	msg->payload.iov_base = (void *)bytes;
}

static void fix_seqack(knot_xdp_msg_t *msg)
{
	knot_tcp_conn_t *conn = tcp_table_find(test_table, msg);
	assert(conn != NULL);
	msg->seqno = conn->seqno;
	msg->ackno = conn->ackno;
}

static void fix_seqacks(knot_xdp_msg_t *msgs, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		fix_seqack(&msgs[i]);
	}
}

void test_syn(void)
{
	knot_xdp_msg_t msg;
	knot_tcp_relay_dynarray_t relays = { 0 };
	prepare_msg(&msg, KNOT_XDP_MSG_SYN, 1, 2);
	int ret = knot_tcp_relay(test_sock, &msg, 1, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "SYN: relay OK");
	is_int(msg.seqno + 1, sent_ackno, "SYN: ackno");
	check_sent(0, 0, 1, 0);
	is_int(1, relays.size, "SYN: one relay");
	knot_tcp_relay_t *rl = &knot_tcp_relay_dynarray_arr(&relays)[0];
	is_int(XDP_TCP_SYN, rl->action, "SYN: relay action");
	is_int(XDP_TCP_NOOP, rl->answer, "SYN: relay answer");
	is_int(0, rl->data.iov_len, "SYN: no payload");
	is_int(1, test_table->usage, "SYN: one connection in table");
	knot_tcp_conn_t *conn = tcp_table_find(test_table, &msg);
	ok(conn != NULL, "SYN: connection present");
	ok(conn == rl->conn, "SYN: relay points to connection");
	is_int(XDP_TCP_ESTABLISHING, conn->state, "SYN: connection state");
	ok(memcmp(&conn->ip_rem, &msg.ip_from, sizeof(msg.ip_from)) == 0, "SYN: conn IP from");
	ok(memcmp(&conn->ip_loc, &msg.ip_to, sizeof(msg.ip_to)) == 0, "SYN: conn IP to");

	knot_tcp_relay_free(&relays);
	test_conn = conn;
}

void test_establish(void)
{
	knot_xdp_msg_t msg;
	knot_tcp_relay_dynarray_t relays = { 0 };
	prepare_msg(&msg, KNOT_XDP_MSG_ACK, 1, 2);
	prepare_seqack(&msg, 0, 1);
	int ret = knot_tcp_relay(test_sock, &msg, 1, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "establish: relay OK");
	check_sent(0, 0, 0, 0);
	is_int(0, relays.size, "establish: no relay");
	/*knot_tcp_relay_t *rl = &knot_tcp_relay_dynarray_arr(&relays)[0];
	is_int(XDP_TCP_ESTABLISH, rl->action, "establish: relay action");
	ok(rl->conn != NULL, "establish: connection present");
	ok(rl->conn == test_conn, "establish: same connection");
	is_int(XDP_TCP_NORMAL, rl->conn->state, "establish: connection state");*/

	knot_tcp_relay_free(&relays);
	clean_table();
}

void test_syn_ack(void)
{
	knot_xdp_msg_t msg;
	knot_tcp_relay_dynarray_t relays = { 0 };
	prepare_msg(&msg, KNOT_XDP_MSG_SYN | KNOT_XDP_MSG_ACK, 1000, 2000);
	int ret = knot_tcp_relay(test_sock, &msg, 1, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "SYN+ACK: relay OK");
	is_int(msg.seqno + 1, sent_ackno, "SYN+ACK: ackno");
	check_sent(1, 0, 0, 0);
	is_int(1, relays.size, "SYN+ACK: one relay");
	knot_tcp_relay_t *rl = &knot_tcp_relay_dynarray_arr(&relays)[0];
	is_int(XDP_TCP_ESTABLISH, rl->action, "SYN+ACK: relay action");
	ok(rl->conn != NULL, "SYN+ACK: connection present");

	test_conn = rl->conn;
	knot_tcp_relay_free(&relays);
}

void test_data_fragments(void)
{
	knot_xdp_msg_t msgs[4];
	knot_tcp_relay_dynarray_t relays = { 0 };

	// first msg contains one whole payload and one fragment
	prepare_msg(&msgs[0], KNOT_XDP_MSG_ACK, 1000, 2000);
	prepare_seqack(&msgs[0], 0, 0);
	prepare_data(&msgs[0], "\x00\x03""xyz""\x00\x04""ab", 9);

	// second msg contains just fragment not completing anything
	prepare_msg(&msgs[1], KNOT_XDP_MSG_ACK, 1000, 2000);
	prepare_seqack(&msgs[1], 9, 0);
	prepare_data(&msgs[1], "c", 1);

	// third msg finishes fragment, contains one whole, and starts new fragment by just half of length info
	prepare_msg(&msgs[2], KNOT_XDP_MSG_ACK, 1000, 2000);
	prepare_seqack(&msgs[2], 10, 0);
	prepare_data(&msgs[2], "d""\x00\x01""i""\x00", 5);

	// fourth msg completes fragment and starts never-finishing one
	prepare_msg(&msgs[3], KNOT_XDP_MSG_ACK, 1000, 2000);
	prepare_seqack(&msgs[3], 15, 0);
	prepare_data(&msgs[3], "\x02""AB""\xff\xff""abcdefghijklmnopqrstuvwxyz...", 34);

	int ret = knot_tcp_relay(test_sock, msgs, sizeof(msgs) / sizeof(msgs[0]),
	                         test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "fragments: relay OK");
	is_int(msgs[3].ackno, sent_seqno, "fragments: seqno");
	is_int(msgs[3].seqno + msgs[3].payload.iov_len, sent_ackno, "fragments: ackno");
	check_sent(4, 0, 0, 0);
	knot_tcp_relay_t *rls = knot_tcp_relay_dynarray_arr(&relays);

	is_int(XDP_TCP_DATA, rls[0].action, "fragments0: action");
	is_int(XDP_TCP_NOOP, rls[0].answer, "fragments0: answer");
	is_int(3, rls[0].data.iov_len, "fragments0: data length");
	ok(memcmp("xyz", rls[0].data.iov_base, rls[0].data.iov_len) == 0, "fragments0: data");
	ok(rls[0].conn != NULL, "fragments0: connection present");
	ok(rls[0].conn == test_conn, "fragments0: same connection");

	is_int(XDP_TCP_DATA, rls[1].action, "fragments1: action");
	is_int(4, rls[1].data.iov_len, "fragments1: data length");
	ok(memcmp("abcd", rls[1].data.iov_base, rls[1].data.iov_len) == 0, "fragments1: data");
	ok(rls[1].conn == test_conn, "fragments1: same connection");

	is_int(XDP_TCP_DATA, rls[2].action, "fragments2: action");
	is_int(1, rls[2].data.iov_len, "fragments2: data length");
	ok(memcmp("i", rls[2].data.iov_base, rls[2].data.iov_len) == 0, "fragments2: data");
	ok(rls[2].conn == test_conn, "fragments2: same connection");

	is_int(XDP_TCP_DATA, rls[3].action, "fragments3: action");
	is_int(2, rls[3].data.iov_len, "fragments3: data length");
	ok(memcmp("AB", rls[3].data.iov_base, rls[3].data.iov_len) == 0, "fragments3: data");
	ok(rls[3].conn == test_conn, "fragments3: same connection");

	knot_tcp_relay_free(&relays);
}

void test_close(void)
{
	size_t conns_pre = test_table->usage;

	knot_xdp_msg_t msg;
	knot_tcp_relay_dynarray_t relays = { 0 };
	prepare_msg(&msg, KNOT_XDP_MSG_FIN | KNOT_XDP_MSG_ACK,
	            be16toh(test_conn->ip_rem.sin6_port),
	            be16toh(test_conn->ip_loc.sin6_port));
	prepare_seqack(&msg, 0, 0);
	int ret = knot_tcp_relay(test_sock, &msg, 1, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "close: relay 1 OK");
	check_sent(0, 0, 0, 1);
	is_int(1, relays.size, "close: one relay");
	knot_tcp_relay_t *rl = &knot_tcp_relay_dynarray_arr(&relays)[0];
	is_int(XDP_TCP_CLOSE, rl->action, "close: relay action");
	ok(rl->conn == test_conn, "close: same connection");
	is_int(XDP_TCP_CLOSING, rl->conn->state, "close: conn state");
	knot_tcp_relay_free(&relays);

	msg.flags &= ~KNOT_XDP_MSG_FIN;
	prepare_seqack(&msg, 0, 0);
	ret = knot_tcp_relay(test_sock, &msg, 1, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "close: relay 2 OK");
	check_sent(0, 0, 0, 0);
	is_int(conns_pre - 1, test_table->usage, "close: connection removed");
	is_int(conns_pre - 1, tcp_table_timeout_length(test_table), "close: timeout list size");
}

void test_many(void)
{
	size_t CONNS = test_table->size * test_table->size;
	size_t i_survive = CONNS / 2;
	uint32_t timeout_time = 1000000;

	knot_xdp_msg_t *msgs = malloc(CONNS * sizeof(*msgs));
	assert(msgs != NULL);
	for (size_t i = 0; i < CONNS; i++) {
		prepare_msg(&msgs[i], KNOT_XDP_MSG_SYN, i + 2, 1);
	}

	knot_tcp_relay_dynarray_t relays = { 0 };
	int ret = knot_tcp_relay(test_sock, msgs, CONNS, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "many: relay OK");
	check_sent(0, 0, CONNS, 0);
	is_int(CONNS, relays.size, "many: relays count");
	is_int(CONNS, test_table->usage, "many: table usage");

	knot_tcp_relay_free(&relays);
	usleep(timeout_time);
	knot_xdp_msg_t *survive = &msgs[i_survive];
	survive->flags = (KNOT_XDP_MSG_TCP | KNOT_XDP_MSG_ACK);
	knot_tcp_conn_t *surv_conn = tcp_table_find(test_table, survive);
	fix_seqack(survive);
	prepare_data(survive, "\x00\x00", 2);
	(void)knot_tcp_relay(test_sock, survive, 1, test_table, NULL, &relays, NULL);
	is_int(1, relays.size, "many/survivor: one relay");
	knot_tcp_relay_t *rl = &knot_tcp_relay_dynarray_arr(&relays)[0];
	clean_sent();

	uint32_t reset_count = 0, close_count = 0;
	ret = knot_tcp_sweep(test_table, test_sock, UINT32_MAX, timeout_time, UINT32_MAX,
	                     0, 0, &close_count, &reset_count);
	is_int(KNOT_EOK, ret, "many/timeout1: OK");
	is_int(CONNS - 1, close_count, "many/timeout1: close count");
	is_int(0, reset_count, "may/timeout1: reset count");
	check_sent(0, 0, 0, CONNS - 1);

	close_count = 0;
	ret = knot_tcp_sweep(test_table, test_sock, UINT32_MAX, UINT32_MAX, timeout_time,
	                     0, 0, &close_count, &reset_count);
	is_int(KNOT_EOK, ret, "many/timeout2: OK");
	is_int(0, close_count, "many/timeout2: close count");
	is_int(CONNS - 1, reset_count, "may/timeout2: reset count");
	check_sent(0, CONNS - 1, 0, 0);
	is_int(1, test_table->usage, "many/timeout: one survivor");
	is_int(1, tcp_table_timeout_length(test_table), "many/timeout: one survivor in timeout list");
	ok(surv_conn != NULL, "many/timeout: survivor connection present");
	ok(surv_conn == rl->conn, "many/timeout: same connection");

	free(msgs);
}

void test_ibufs_size(void)
{
	int CONNS = 4;
	knot_xdp_msg_t msgs[CONNS];
	knot_tcp_relay_dynarray_t relays = { 0 };

	// just open connections
	for (int i = 0; i < CONNS; i++) {
		prepare_msg(&msgs[i], KNOT_XDP_MSG_SYN, i + 2000, 1);
	}
	int ret = knot_tcp_relay(test_sock, msgs, CONNS, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "ibufs: open OK");
	check_sent(0, 0, CONNS, 0);
	for (int i = 0; i < CONNS; i++) {
		msgs[i].flags = KNOT_XDP_MSG_TCP | KNOT_XDP_MSG_ACK;
	}

	is_int(0, test_table->inbufs_total, "inbufs: initial total zero");

	// first connection will start a fragment buf then finish it
	fix_seqack(&msgs[0]);
	prepare_data(&msgs[0], "\x00\x0a""lorem", 7);
	ret = knot_tcp_relay(test_sock, &msgs[0], 1, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "ibufs: must be OK");
	check_sent(1, 0, 0, 0);
	is_int(7, test_table->inbufs_total, "inbufs: first inbuf");
	knot_tcp_relay_free(&relays);

	// other connection will just store fragments
	fix_seqacks(msgs, CONNS);
	prepare_data(&msgs[0], "ipsum", 5);
	prepare_data(&msgs[1], "\x00\xff""12345", 7);
	prepare_data(&msgs[2], "\xff\xff""abcde", 7);
	prepare_data(&msgs[3], "\xff\xff""abcde", 7);
	ret = knot_tcp_relay(test_sock, msgs, CONNS, test_table, NULL, &relays, NULL);
	is_int(KNOT_EOK, ret, "inbufs: relay OK");
	check_sent(CONNS, 0, 0, 0);
	is_int(21, test_table->inbufs_total, "inbufs: after change");
	is_int(1, relays.size, "inbufs: one relay");
	is_int(10, knot_tcp_relay_dynarray_arr(&relays)[0].data.iov_len, "inbufs: data length");
	knot_tcp_relay_free(&relays);

	// now free some
	uint32_t reset_count = 0, close_count = 0;
	ret = knot_tcp_sweep(test_table, test_sock, UINT32_MAX, UINT32_MAX, UINT32_MAX,
	                     0, 8, &close_count, &reset_count);
	is_int(KNOT_EOK, ret, "inbufs: timeout OK");
	check_sent(0, 2, 0, 0);
	is_int(0, close_count, "inbufs: close count");
	is_int(2, reset_count, "inbufs: reset count");
	is_int(7, test_table->inbufs_total, "inbufs: final state");
	ok(NULL != tcp_table_find(test_table, &msgs[0]), "inbufs: first conn survived");
	ok(NULL == tcp_table_find(test_table, &msgs[1]), "inbufs: second conn not survived");
	ok(NULL == tcp_table_find(test_table, &msgs[2]), "inbufs: third conn not survived");
	ok(NULL != tcp_table_find(test_table, &msgs[3]), "inbufs: fourth conn survived");

	clean_table();
}

static void init_mock(knot_xdp_socket_t **socket, void *send_mock)
{
	*socket = calloc(1, sizeof(**socket));
	if (*socket != NULL) {
		(*socket)->send_mock = send_mock;
	}
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_table = knot_tcp_table_new(TEST_TABLE_SIZE);
	assert(test_table != NULL);

	init_mock(&test_sock, mock_send);

	test_syn();
	test_establish();

	test_syn_ack();
	test_data_fragments();
	test_close();

	test_ibufs_size();

	knot_xdp_deinit(test_sock);
	init_mock(&test_sock, mock_send_nocheck);
	test_many();

	knot_xdp_deinit(test_sock);
	knot_tcp_table_free(test_table);

	return 0;
}
