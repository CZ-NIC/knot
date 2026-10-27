/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils/common/msg.h"
#include "utils/common/netio.h"

knot_dynarray_define(util_msg, util_msg_event_t, DYNARRAY_VISIBILITY_NORMAL);

jsonw_t *g_json = NULL;
util_msg_dynarray_t g_json_events = { 0 };

static volatile int MSG_DBG_STATE = 0; /* Positive if debugging is enabled. */

int msg_enable_debug(int level)
{
	return MSG_DBG_STATE = level;
}

int msg_debug(int level, const char *fmt, ...)
{
	int n = 0;
	if (MSG_DBG_STATE >= level) {
		va_list ap;
		va_start(ap, fmt);
		n = vprintf(fmt, ap);
		va_end(ap);
	}
	return n;
}

void utils_json_event_add(const char *msg, ...)
{
	util_msg_event_t *e = (g_json == NULL ? NULL : util_msg_dynarray_add(&g_json_events, NULL));
	if (e != NULL) {
		e->type[0] = '\0';
		va_list args;
		va_start(args, msg);
		vsnprintf(e->text, sizeof(e->text), msg, args);
		va_end(args);
	}
}

void utils_json_events_dump(void)
{
	if (g_json == NULL || g_json_events.size < 1) {
		return;
	}
	jsonw_list(g_json, "events");
	knot_dynarray_foreach(util_msg, util_msg_event_t, e, g_json_events) {
		jsonw_object(g_json, NULL);
		if (e->type[0] != '\0') {
			jsonw_str(g_json, "type", e->type);
		}
		jsonw_str(g_json, "text", e->text);
		jsonw_end(g_json);
	}
	jsonw_end(g_json);
	util_msg_dynarray_free(&g_json_events);
}

static void jsonw_addr(jsonw_t *j, const char *msg, const struct sockaddr_storage *ss)
{
	char buf[64] = { 0 };
	if (sockaddr_tostr(buf, sizeof(buf), ss) > 0) {
		char *port = strchr(buf, '@');
		if (port != NULL) {
			*port = '\0';
		}
		jsonw_str(j, msg, buf);
	}
}

// TODO: move to netio.c ?
void utils_json_transport(const struct utils_net *net)
{
	if (g_json != NULL && net != NULL) {
		const struct sockaddr_storage *remote_ip = (const struct sockaddr_storage *)net->srv->ai_addr;
		const struct sockaddr_storage local_placeholder = { .ss_family = remote_ip->ss_family };
		const struct sockaddr_storage *local_ip = (net->local_info == NULL ? &local_placeholder : (const struct sockaddr_storage *)net->local_info->ai_addr);

		jsonw_addr(g_json, "responseAddress", remote_ip);
		jsonw_int(g_json, "responsePort", sockaddr_port(remote_ip));
		jsonw_addr(g_json, "queryAddress", local_ip);
		jsonw_int(g_json, "queryPort", sockaddr_port(local_ip));

		jsonw_str(g_json, "socketProtocol", get_protocol_str(get_protocol(net)));

		jsonw_object(g_json, "transport");
#ifdef ENABLE_QUIC
		if (net->quic.params.enable) {
			print_quic_json(g_json, &net->quic);
			print_tls_json(g_json, net->quic.tls);
		} else
#endif
		{
			print_tls_json(g_json, &net->tls);
#ifdef LIBNGHTTP2
			print_https_json(g_json, &net->https);
#endif
		}
		jsonw_end(g_json);
	}
}

void utils_json_error(const char *msg, ...)
{
	char buf[256];
	va_list args;
	va_start(args, msg);
	int pret = vsnprintf(buf, sizeof(buf), msg, args);
	va_end(args);
	if (g_json == NULL || pret < 0) {
		return;
	}
	jsonw_object(g_json, NULL);
	jsonw_str(g_json, "type", "ERROR");
	utils_json_events_dump();
	jsonw_object(g_json, "error");
	jsonw_str(g_json, "text", buf);
	jsonw_end(g_json);
	jsonw_end(g_json);
}
