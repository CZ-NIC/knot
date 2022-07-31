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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "utils/kxdpgun/ip_route.h"
#include "contrib/sockaddr.h"

#define ROUTE_LOOKUP_LOOP_LIMIT 10000

static size_t addr_len(int family)
{
	switch (family) {
	case AF_INET:
		return sizeof(struct in_addr);
	case AF_INET6:
		return sizeof(struct in6_addr);
	default:
		return 0;
	}
}

static int send_dummy_pkt(const struct sockaddr_storage *ip)
{
	static const uint8_t dummy_pkt[] = {
		// dummy data
		0x08, 0x00, 0xec, 0x72, 0x0b, 0x87, 0x00, 0x06,

		//padding
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	int fd = socket(ip->ss_family, SOCK_RAW,
	                ip->ss_family == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
	if (fd < 0) {
		return -errno;
	}
	int ret = sendto(fd, dummy_pkt, sizeof(dummy_pkt), 0, (const struct sockaddr *)ip,
	                 ip->ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) :
	                                             sizeof(struct sockaddr_in));
	if (ret < 0) {
		ret = -errno;
	}
	close(fd);
	return ret;
}

static int netlink_query(int family, uint16_t type, mnl_cb_t cb, void *data,
                         void *qextra, size_t qextra_len, uint16_t qextra_type)
{
	// open and bind NETLINK socket
	struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		return -errno;
	}
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		mnl_socket_close(nl);
		return -errno;
	}
	unsigned portid = mnl_socket_get_portid(nl);
	int ret = 0;

	// allocate request
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	if (nlh == NULL) {
		ret = -ENOMEM;
		goto end;
	}
	unsigned seq = time(NULL);
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
	if (rtm == NULL) {
		ret = -ENOMEM;
		goto end;
	}

	if (qextra_len > 0) {
		nlh->nlmsg_flags = NLM_F_REQUEST;
		rtm->rtm_dst_len = qextra_len * 8; // 8 bits per byte
		mnl_attr_put(nlh, qextra_type, qextra_len, qextra);
	}

	// send request
	rtm->rtm_family = family;
	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (ret < 0) {
		ret = -errno;
		goto end;
	}

	// collect replies with callback
	while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, cb, data);
		if (ret <= MNL_CB_STOP) {
			break;
		}
		if (qextra_len > 0) {
			break;
		}
	}
	ret = ret < 0 ? -errno : 0;

end:
	mnl_socket_close(nl);
	return ret;
}

typedef struct {
	const struct sockaddr_storage *ip;
	struct sockaddr_storage *via;
	struct sockaddr_storage *src;
	char *dev;
	uint64_t priority; // top 32 bits: unmatched address bits; bottom 32 bits: route metric priority
	unsigned match;

	// intermediate callback data
	const struct nlattr *tb[RTA_MAX+1];
} ip_route_get_ctx_t;

static int validate_attr_route(const struct nlattr *attr, void *data)
{
	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, RTA_MAX) < 0) {
		return MNL_CB_OK;
	}

	ip_route_get_ctx_t *ctx = data;

	int type = mnl_attr_get_type(attr);
	switch(type) {
	case RTA_TABLE:
	case RTA_OIF:
	case RTA_FLOW:
	case RTA_PRIORITY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case RTA_DST:
	case RTA_SRC:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, addr_len(ctx->ip->ss_family)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case RTA_METRICS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	}
	ctx->tb[type] = attr;
	return MNL_CB_OK;
}

static void attr2addr(const struct nlattr *attr, int family, struct sockaddr_storage *out)
{
	if (attr == NULL) {
		out->ss_family = AF_UNSPEC;
		return;
	}
	out->ss_family = family;
	if (family == AF_INET6) {
		struct in6_addr *addr = mnl_attr_get_payload(attr);
		memcpy(&((struct sockaddr_in6 *)out)->sin6_addr, addr, sizeof(*addr));
	} else {
		struct in_addr *addr = mnl_attr_get_payload(attr);
		memcpy(&((struct sockaddr_in *)out)->sin_addr, addr, sizeof(*addr));
	}
}

static void attr2dev(const struct nlattr *attr, char *out) // out must have IFNAMSIZ length
{
	*out = '\0';

	if (attr != NULL) {
		if_indextoname(mnl_attr_get_u32(attr), out);
	}
}

static uint32_t attr2prio(const struct nlattr *attr)
{
	if (attr == NULL) {
		return 0; // 0 is the default metric priority in linux
	}
	return mnl_attr_get_u32(attr);
}

static int ip_route_get_cb(const struct nlmsghdr *nlh, void *data)
{
	ip_route_get_ctx_t *ctx = data;
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
	if (rm->rtm_family != ctx->ip->ss_family) {
		return MNL_CB_ERROR;
	}

	mnl_attr_parse(nlh, sizeof(*rm), validate_attr_route, data);

	uint64_t new_metric = addr_len(rm->rtm_family) * 8 - rm->rtm_dst_len;
	new_metric = (new_metric << 32) + attr2prio(ctx->tb[RTA_PRIORITY]);
	if (new_metric >= ctx->priority) {
		return MNL_CB_OK;
	}

	struct sockaddr_storage dst;
	attr2addr(ctx->tb[RTA_DST], rm->rtm_family, &dst);

	if (rm->rtm_dst_len == 0 ||
	    sockaddr_net_match(&dst, ctx->ip, rm->rtm_dst_len)) {
		attr2addr(ctx->tb[RTA_PREFSRC], rm->rtm_family, ctx->src);
		attr2addr(ctx->tb[RTA_GATEWAY], rm->rtm_family, ctx->via);
		attr2dev(ctx->tb[RTA_OIF], ctx->dev);
		ctx->match++;
		ctx->priority = new_metric;
	}

	memset(ctx->tb, 0, sizeof(void *) * (RTA_MAX+1));
	return MNL_CB_OK;
}

int ip_route_get(const struct sockaddr_storage *ip,
                 struct sockaddr_storage *via,
                 struct sockaddr_storage *src,
                 char *dev)
{
	struct sockaddr_storage last_via = { 0 };
	ip_route_get_ctx_t ctx = { ip, &last_via, src, dev, 0, 0 };
	do {
		ctx.priority = UINT64_MAX;

		size_t qextra_len;
		void *qextra = sockaddr_raw(ip, &qextra_len);
		int ret = netlink_query(ip->ss_family, RTM_GETROUTE,
		                        ip_route_get_cb, &ctx, qextra,
		                        qextra_len, IFA_ADDRESS);
		if (ret != 0) {
			return ret;
		}
		if (last_via.ss_family == ip->ss_family) { // not AF_UNSPEC
			memcpy(via, &last_via, sizeof(*via));
		}

		// next loop will search for path to "via"
		ctx.ip = via;
	} while (last_via.ss_family != AF_UNSPEC &&
	         ctx.priority != UINT64_MAX && // avoid loop when nothing found
	         ctx.match < ROUTE_LOOKUP_LOOP_LIMIT);  // avoid loop when looped route

	return src->ss_family == ip->ss_family ? 0 : -ENOENT;
}

typedef struct {
	const struct sockaddr_storage *ip;
	uint8_t *mac;
	unsigned match;

	// intermediate callback data
	const struct nlattr *tb[RTA_MAX+1];
} ip_neigh_ctx_t;

static int validate_attr_neigh(const struct nlattr *attr, void *data)
{
	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, NDA_MAX) < 0) {
		return MNL_CB_OK;
	}

	ip_neigh_ctx_t *ctx = data;

	int type = mnl_attr_get_type(attr);
	switch (type) {
	case NDA_DST:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, addr_len(ctx->ip->ss_family)) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	case NDA_LLADDR:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, ETH_ALEN) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	}

	ctx->tb[type] = attr;
	return MNL_CB_OK;
}

static int ip_neigh_cb(const struct nlmsghdr *nlh, void *data)
{
	ip_neigh_ctx_t *ctx = data;
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);
	if (rm->rtm_family != ctx->ip->ss_family) {
		return MNL_CB_ERROR;
	}

	mnl_attr_parse(nlh, sizeof(*rm), validate_attr_neigh, data);

	struct sockaddr_storage dst;
	attr2addr(ctx->tb[NDA_DST], rm->rtm_family, &dst);

	if (sockaddr_cmp((struct sockaddr_storage *)&dst, (struct sockaddr_storage *)ctx->ip, true) == 0 &&
	    ctx->tb[NDA_LLADDR] != NULL) {
		memcpy(ctx->mac, mnl_attr_get_payload(ctx->tb[NDA_LLADDR]), ETH_ALEN);
		ctx->match++;
	}

	memset(ctx->tb, 0, sizeof(void *) * (RTA_MAX+1));
	return MNL_CB_OK;
}

int ip_neigh_get(const struct sockaddr_storage *ip, bool dummy_sendto, uint8_t *mac)
{
	if (dummy_sendto) {
		int ret = send_dummy_pkt(ip);
		if (ret < 0) {
			return ret;
		}
		usleep(10000);
	}
	ip_neigh_ctx_t ctx = { ip, mac, 0 };
	int ret = netlink_query(ip->ss_family, RTM_GETNEIGH, ip_neigh_cb, &ctx,
	                        NULL, 0, 0);
	if (ret == 0 && ctx.match == 0) {
		return -ENOENT;
	}
	return ret;
}
