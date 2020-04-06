﻿/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <ifaddrs.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "contrib/openbsd/strlcpy.h"
#include "contrib/sockaddr.h"
#include "libknot/attribute.h"
#include "libknot/errcode.h"
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
		.ifr_data = &ch
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
