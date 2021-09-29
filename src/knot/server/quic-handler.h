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

#pragma once

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include "contrib/mempattern.h"
#include "contrib/ucw/lists.h"
#include "libknot/packet/wire.h"
#include "udp-handler.h"

#define QUIC_SV_SCIDLEN 18

typedef struct knot_quic_conn {
	ngtcp2_cid scid;
	ngtcp2_cid dcid;
	ngtcp2_conn *conn;
	struct knot_quic_conn *next;
	gnutls_session_t tls_session;
} knot_quic_conn_t;

typedef struct knot_quic_table_pair {
	ngtcp2_cid key;
	knot_quic_conn_t *value;
	struct knot_quic_table_pair *next;
} knot_quic_table_pair_t;

typedef struct {
	size_t size;
	// size_t usage;
	// size_t inbufs_total;
	knot_quic_table_pair_t *conns[];
	//knot_mm_t mem;
} knot_quic_table_t;

typedef struct {
	gnutls_certificate_credentials_t tls_cert;
	gnutls_anti_replay_t tls_anti_replay;
	gnutls_datum_t tls_ticket_key;
	uint8_t static_secret[32];
} knot_quic_creds_t;

struct quic_recvfrom {
	int fd;
	struct sockaddr_storage addr;
	struct msghdr msg[NBUFS];
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	cmsg_pktinfo_t pktinfo;
	knot_quic_creds_t tls_creds;
	knot_quic_table_t *conns;
};

unsigned int knot_quic_msghdr_ecn(struct msghdr *msg, const int family);
int knot_quic_msghdr_local_addr(const struct msghdr *msg, const int family, struct sockaddr_storage *local_addr, size_t *addr_len);

int knot_quic_send_version_negotiation(struct quic_recvfrom *rq);

uint64_t knot_quic_cid_hash(const ngtcp2_cid *dcid);

knot_quic_conn_t *knot_quic_conn_alloc(void);
int knot_quic_conn_init(knot_quic_conn_t *conn, const knot_quic_creds_t *creds, const ngtcp2_path *local_addr, const ngtcp2_cid *scid, const ngtcp2_cid *dcid, const ngtcp2_cid *ocid, const uint32_t version);
knot_quic_conn_t *knot_quic_conn_new(const knot_quic_creds_t *creds, const ngtcp2_path *path, const ngtcp2_cid *scid, const ngtcp2_cid *dcid, const ngtcp2_cid *ocid, const uint32_t version);
int knot_quic_conn_on_read(struct quic_recvfrom *rq, knot_quic_conn_t *conn,
                           ngtcp2_pkt_info *pi, uint8_t *data, size_t datalen);
int knot_quic_conn_on_write(knot_quic_conn_t *conn);

knot_quic_table_t *knot_quic_table_new(size_t size);
int knot_quic_table_store(knot_quic_table_t *table, const ngtcp2_cid *dcid, knot_quic_conn_t *el);
knot_quic_conn_t *knot_quic_table_find(knot_quic_table_t *table, const ngtcp2_cid *dcid);
knot_quic_conn_t *knot_quic_table_find_dcid(knot_quic_table_t *table, const uint8_t *cid, const size_t cidlen);