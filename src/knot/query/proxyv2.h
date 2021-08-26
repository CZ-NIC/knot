#pragma once

#include <sys/socket.h>
#include <stddef.h>

#include "libknot/mm_ctx.h"
#include "libknot/packet/pkt.h"
#include "knot/include/module.h"
#include "contrib/sockaddr.h"

int proxyv2_decapsulate(void *base,
			size_t len_base,
			knot_pkt_t **query,
			knotd_qdata_params_t *params,
			struct sockaddr_storage *client,
			knot_mm_t *mm);
