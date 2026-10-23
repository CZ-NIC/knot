/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils/common/msg.h"

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
