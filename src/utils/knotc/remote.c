/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/ctl/remote.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "utils/knotc/remote.h"

static int cmd_remote_print_reply(const knot_rrset_t *rr)
{
	if (rr->type != KNOT_RRTYPE_TXT) {
		return KNOT_EMALF;
	}

	uint16_t rr_count = rr->rrs.rr_count;
	for (uint16_t i = 0; i < rr_count; i++) {
		/* Parse TXT. */
		remote_print_txt(rr, i);
	}

	return KNOT_EOK;
}

static int cmd_remote_reply(int c, struct timeval *timeout)
{
	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, NULL);
	if (!pkt) {
		return KNOT_ENOMEM;
	}

	/* Read response packet. */
	int n = net_dns_tcp_recv(c, pkt->wire, pkt->max_size, timeout);
	if (n <= 0) {
		knot_pkt_free(&pkt);
		return KNOT_ECONN;
	} else {
		pkt->size = n;
	}

	/* Parse packet and check response. */
	int ret = remote_parse(pkt);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&pkt);
		return ret;
	}

	/* Check RCODE */
	const knot_pktsection_t *authority = knot_pkt_section(pkt, KNOT_AUTHORITY);
	ret = knot_wire_get_rcode(pkt->wire);
	switch(ret) {
	case KNOT_RCODE_NOERROR:
		if (authority->count > 0) {
			ret = cmd_remote_print_reply(knot_pkt_rr(authority, 0));
		}
		break;
	case KNOT_RCODE_REFUSED:
		ret = KNOT_EDENIED;
		break;
	default:
		ret = KNOT_ERROR;
		break;
	}

	knot_pkt_free(&pkt);
	return ret;
}

int cmd_remote(const char *socket, const char *cmd, uint16_t rrt,
               int argc, char *argv[])
{
	int rc = 0;

	/* Make query. */
	knot_pkt_t *pkt = remote_query(cmd);
	if (!pkt) {
		log_error("failed to prepare query for '%s'", cmd);
		return 1;
	}

	/* Build query data. */
	knot_pkt_begin(pkt, KNOT_AUTHORITY);
	if (argc > 0) {
		knot_rrset_t rr;
		int res = remote_build_rr(&rr, "data.", rrt);
		if (res != KNOT_EOK) {
			log_error("failed to create the query");
			knot_pkt_free(&pkt);
			return 1;
		}
		for (uint16_t i = 0; i < argc; ++i) {
			switch(rrt) {
			case KNOT_RRTYPE_NS:
				remote_create_ns(&rr, argv[i]);
				break;
			case KNOT_RRTYPE_TXT:
			default:
				remote_create_txt(&rr, argv[i], strlen(argv[i]), i);
				break;
			}
		}
		res = knot_pkt_put(pkt, 0, &rr, KNOT_PF_FREE);
		if (res != KNOT_EOK) {
			log_error("failed to create the query");
			knot_rrset_clear(&rr, NULL);
			knot_pkt_free(&pkt);
			return 1;
		}
	}

	/* Default timeout. */
	conf_val_t *val = &conf()->cache.srv_tcp_reply_timeout;
	const struct timeval tv_reply = { conf_int(val), 0 };

	/* Prepare socket address. */
	struct sockaddr_storage addr;
	int ret = sockaddr_set(&addr, AF_UNIX, socket, 0);
	if (ret != KNOT_EOK) {
		log_error("failed to connect to socket '%s' (%s)", socket,
		          knot_strerror(ret));
		knot_pkt_free(&pkt);
		return 1;
	}

	/* Connect to socket. */
	int s = net_connected_socket(SOCK_STREAM, &addr, NULL);
	if (s < 0) {
		log_error("failed to connect to socket '%s' (%s)", socket,
		          knot_strerror(s));
		knot_pkt_free(&pkt);
		return 1;
	}

	/* Send and free packet. */
	struct timeval tv = tv_reply;
	ret = net_dns_tcp_send(s, pkt->wire, pkt->size, &tv);
	knot_pkt_free(&pkt);

	/* Evaluate and wait for reply. */
	if (ret <= 0) {
		log_error("failed to connect to socket '%s' (%s)", socket,
		          knot_strerror(ret));
		close(s);
		return 1;
	}

	/* Wait for reply. */
	ret = KNOT_EOK;
	while (ret == KNOT_EOK) {
		tv = tv_reply;
		ret = cmd_remote_reply(s, &tv);
		if (ret != KNOT_EOK) {
			if (ret != KNOT_ECONN) {
				log_error("remote command reply: %s",
				          knot_strerror(ret));
				rc = 1;
			}
			break;
		}
	}

	/* Cleanup. */
	if (rc == 0) {
		printf("\n");
	}

	/* Close connection. */
	close(s);
	return rc;
}
