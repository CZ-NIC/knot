#include "libknot/netlink.h"

#include <errno.h>
#include <time.h>

#include "libknot/attribute.h"

#ifndef MNL_SOCKET_DUMP_SIZE
	#define MNL_SOCKET_DUMP_SIZE	32768
#endif

_public_
int knot_netlink_query(int bus, uint16_t type, init_cb_t init, void *init_data,
                       mnl_cb_t cb, void *cb_data)
{
	// open and bind NETLINK socket
	struct mnl_socket *nl = mnl_socket_open(bus);
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
	char buf[MNL_SOCKET_DUMP_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	if (nlh == NULL) {
		ret = -ENOMEM;
		goto end;
	}
	unsigned seq = time(NULL);
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	if (init != NULL) {
		init(nlh, init_data);
	}

	// send request
	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (ret < 0) {
		ret = -errno;
		goto end;
	}

	// collect replies with callback
	while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, cb, cb_data);
		if (ret <= MNL_CB_STOP) {
			break;
		}
	}
	ret = ret < 0 ? -errno : 0;

end:
	mnl_socket_close(nl);
	return ret;
}