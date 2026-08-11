#pragma once

#include <libmnl/libmnl.h>
#include <linux/ethtool.h>

#ifndef RXH_XFRM_SYM_XOR
	#define	RXH_XFRM_SYM_XOR	0
#endif
#ifndef RXH_XFRM_SYM_OR_XOR
	#define	RXH_XFRM_SYM_OR_XOR	0
#endif

typedef int (*init_cb_t)(struct nlmsghdr *, void *);

int knot_netlink_query(int bus, uint16_t type, init_cb_t init, void *init_data,
                       mnl_cb_t cb, void *cb_data);
