/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/ethtool.h>
#include <linux/ethtool_netlink.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "contrib/openbsd/strlcpy.h"
#include "contrib/sockaddr.h"
#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "libknot/netlink.h"
#include "libknot/xdp/eth.h"

_public_
int knot_eth_queues(const char *devname)
{
	if (devname == NULL) {
		return KNOT_EINVAL;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return knot_map_errno();
	}

	struct ethtool_channels ch = {
		.cmd = ETHTOOL_GCHANNELS
	};
	struct ifreq ifr = {
		.ifr_data = (char *)&ch
	};
	strlcpy(ifr.ifr_name, devname, IFNAMSIZ);

	int ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret != 0) {
		if (errno == EOPNOTSUPP) {
			ret = 1;
		} else {
			ret = knot_map_errno();
		}
	} else {
		if (ch.combined_count == 0) {
			ret = 1;
		} else {
			ret = ch.combined_count;
		}
	}

	close(fd);
	return ret;
}

static int get_ethtool_id_init(struct nlmsghdr *nlh, void *user_data)
{
	struct genlmsghdr *genl = mnl_nlmsg_put_extra_header(nlh, sizeof(*genl));
	if (genl == NULL) {
		return -ENOMEM;
	}
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, ETHTOOL_GENL_NAME);

	return 0;
}

static int cb_ctrl_family(const struct nlmsghdr *nlh, void *data) {
	uint16_t *out_family_id = data;
	struct nlattr *attr;

	mnl_attr_for_each(attr, nlh, sizeof(struct genlmsghdr)) {
		if (mnl_attr_get_type(attr) == CTRL_ATTR_FAMILY_ID) {
			*out_family_id = mnl_attr_get_u16(attr);
			return MNL_CB_STOP;
		}
	}
	return MNL_CB_OK;
}

static int get_rss_xfmr_init(struct nlmsghdr *nlh, void *user_data)
{
	struct genlmsghdr *genl = mnl_nlmsg_put_extra_header(nlh, sizeof(*genl));
	if (genl == NULL) {
		return -ENOMEM;
	}
	genl->cmd = ETHTOOL_MSG_RSS_GET;
	genl->version = ETHTOOL_GENL_VERSION;

	struct nlattr *nest = mnl_attr_nest_start(nlh, ETHTOOL_A_RSS_HEADER);
	mnl_attr_put_strz(nlh, ETHTOOL_A_HEADER_DEV_NAME, (const char *)user_data);
	mnl_attr_nest_end(nlh, nest);

	return 0;
}

static int attr_cb(const struct nlattr *attr, void *data) {
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, ETHTOOL_A_RSS_MAX) < 0) {
		return MNL_CB_ERROR;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int cb_rss_msg(const struct nlmsghdr *nlh, void *data) {
	assert(data != NULL);

	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[ETHTOOL_A_RSS_MAX] = {0};
	uint32_t *val = data;

	mnl_attr_parse(nlh, sizeof(*genl), attr_cb, tb);
	if (tb[ETHTOOL_A_RSS_INPUT_XFRM]) {
		*val = mnl_attr_get_u32(tb[ETHTOOL_A_RSS_INPUT_XFRM]);
	} else {
		*val = 0;
	}

	return MNL_CB_STOP;
}

static int link_get_rss_xfmr(const char *ifname)
{
	uint16_t ethtool_id = 0;
	int ret = 0;
	ret = knot_netlink_query(NETLINK_GENERIC, GENL_ID_CTRL, get_ethtool_id_init,
	                         NULL, cb_ctrl_family, &ethtool_id);
	if (ret < 0) {
		return ret;
	}

	uint32_t flags = 0;
	ret = knot_netlink_query(NETLINK_GENERIC, ethtool_id, get_rss_xfmr_init,
	                         (void *)ifname, cb_rss_msg, &flags);
	if (ret < 0) {
		return ret;
	}
	return flags;
}

_public_
int knot_eth_rss(const char *devname, knot_eth_rss_conf_t **rss_conf)
{
	if (devname == NULL || rss_conf == NULL) {
		return KNOT_EINVAL;
	}

	struct ethtool_rxfh *ctx = NULL;
	knot_eth_rss_conf_t *out = NULL;
	int ret = KNOT_ERROR;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return knot_map_errno();
	}

	struct ethtool_rxfh sizes = {
		.cmd = ETHTOOL_GRSSH
	};
	struct ifreq ifr = {
		.ifr_data = (char *)&sizes
	};
	strlcpy(ifr.ifr_name, devname, IFNAMSIZ);

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret != 0) {
		ret = knot_map_errno();
		goto finish;
	}

	int xfmr = link_get_rss_xfmr(devname);

	const unsigned data_size = sizes.indir_size * sizeof(sizes.rss_config[0]) +
	                           sizes.key_size;

	ctx = calloc(1, sizeof(*ctx) + data_size);
	if (ctx == NULL) {
		ret = KNOT_ENOMEM;
		goto finish;
	}
	ctx->cmd = ETHTOOL_GRSSH;
	ctx->indir_size = sizes.indir_size;
	ctx->key_size = sizes.key_size;
	ifr.ifr_data = (char *)ctx;

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret != 0) {
		ret = knot_map_errno();
		goto finish;
	}

	out = calloc(1, sizeof(*out) + data_size);
	if (out == NULL) {
		ret = KNOT_ENOMEM;
		goto finish;
	}

	out->table_size = sizes.indir_size;
	out->key_size = sizes.key_size;
	memcpy(out->data, ctx->rss_config, data_size);
	out->mask = out->table_size - 1;
	if (xfmr >= 0) {
		out->rss_xfmr = xfmr & (RXH_XFRM_SYM_XOR | RXH_XFRM_SYM_OR_XOR);
	}

finish:
	*rss_conf = out;

	free(ctx);
	close(fd);
	return ret;
}

_public_
int knot_eth_mtu(const char *devname)
{
	if (devname == NULL) {
		return KNOT_EINVAL;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return knot_map_errno();
	}

	struct ifreq ifr = { 0 };
	strlcpy(ifr.ifr_name, devname, IFNAMSIZ);

	int ret = ioctl(fd, SIOCGIFMTU, &ifr);
	if (ret != 0) {
		if (errno == EOPNOTSUPP) {
			ret = KNOT_ENOTSUP;
		} else {
			ret = knot_map_errno();
		}
	} else {
		ret = ifr.ifr_mtu;
	}

	close(fd);
	return ret;
}

_public_
int knot_eth_name_from_addr(const struct sockaddr_storage *addr, char *out,
                            size_t out_len)
{
	if (addr == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	struct ifaddrs *ifaces = NULL;
	if (getifaddrs(&ifaces) != 0) {
		return -errno;
	}

	size_t matches = 0;
	char *match_name = NULL;

	for (struct ifaddrs *ifa = ifaces; ifa != NULL; ifa = ifa->ifa_next) {
		const struct sockaddr_storage *ifss = (struct sockaddr_storage *)ifa->ifa_addr;
		if (ifss == NULL) { // Observed on interfaces without any address.
			continue;
		}

		if ((ifss->ss_family == addr->ss_family && sockaddr_is_any(addr)) ||
		    sockaddr_cmp(ifss, addr, true) == 0) {
			matches++;
			match_name = ifa->ifa_name;
		}
	}

	if (matches == 1) {
		size_t len = strlcpy(out, match_name, out_len);
		freeifaddrs(ifaces);
		return (len >= out_len) ? KNOT_ESPACE : KNOT_EOK;
	}

	freeifaddrs(ifaces);
	return matches == 0 ? KNOT_EADDRNOTAVAIL : KNOT_ELIMIT;
}

_public_
int knot_eth_vlans(uint16_t *vlan_map[], uint16_t *vlan_map_max)
{
	if (vlan_map == NULL || vlan_map_max == NULL) {
		return KNOT_EINVAL;
	}

	struct ifaddrs *ifaces = NULL;
	if (getifaddrs(&ifaces) != 0) {
		return knot_map_errno();
	}

	unsigned map_size = 0;
	for (struct ifaddrs *ifa = ifaces; ifa != NULL; ifa = ifa->ifa_next) {
		map_size++;
	}

	uint16_t *map = calloc(sizeof(uint16_t), 1 + map_size); // Indexed from 1.
	if (map == NULL) {
		freeifaddrs(ifaces);
		return KNOT_ENOMEM;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		free(map);
		freeifaddrs(ifaces);
		return knot_map_errno();
	}

	for (struct ifaddrs *ifa = ifaces; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET) {
			continue;
		}

		unsigned if_index = if_nametoindex(ifa->ifa_name);
		if (if_index == 0) {
			close(fd);
			free(map);
			freeifaddrs(ifaces);
			return knot_map_errno();
		}

		struct vlan_ioctl_args ifv = {
			.cmd = GET_VLAN_REALDEV_NAME_CMD
		};
		strlcpy(ifv.device1, ifa->ifa_name, sizeof(ifv.device1));

		if (ioctl(fd, SIOCGIFVLAN, &ifv) >= 0) {
			memset(&ifv, 0, sizeof(ifv));
			ifv.cmd = GET_VLAN_VID_CMD;
			strlcpy(ifv.device1, ifa->ifa_name, sizeof(ifv.device1));

			if (ioctl(fd, SIOCGIFVLAN, &ifv) < 0) {
				close(fd);
				free(map);
				freeifaddrs(ifaces);
				return knot_map_errno();
			}

			map[if_index] = htobe16(ifv.u.VID);
		}
	}

	close(fd);
	freeifaddrs(ifaces);

	*vlan_map = map;
	*vlan_map_max = map_size;

	return KNOT_EOK;
}

_public_
knot_xdp_mode_t knot_eth_xdp_mode(int if_index)
{
#if USE_LIBXDP
	struct bpf_xdp_query_opts info = { .sz = sizeof(info) };
	int ret = bpf_xdp_query(if_index, 0, &info);
#else
	struct xdp_link_info info;
	int ret = bpf_get_link_xdp_info(if_index, &info, sizeof(info), 0);
#endif
	if (ret != 0) {
		return KNOT_XDP_MODE_NONE;
	}

	switch (info.attach_mode) {
	case XDP_ATTACHED_DRV:
	case XDP_ATTACHED_HW:
		return KNOT_XDP_MODE_FULL;
	case XDP_ATTACHED_SKB:
		return KNOT_XDP_MODE_EMUL;
	default:
		return KNOT_XDP_MODE_NONE;
	}
}
