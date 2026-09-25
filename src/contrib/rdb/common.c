/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <poll.h>
#include <string.h>

#include "contrib/rdb/common.h"

#ifdef ENABLE_REDIS

bool rdb_compatible(redisContext *rdb)
{
	if (rdb == NULL) {
		return false;
	}

#ifdef ENDIANITY_LITTLE
  #define ENDIAN 1
#else
  #define ENDIAN 0
#endif

	const char *lua = "local n=1; local s=string.dump(function() return n end); " \
	                  "local e=string.byte(s,7); if e==0 then return 0 else return 1 end";

	redisReply *reply = redisCommand(rdb, "EVAL %s 0", lua);
	bool res = (reply != NULL &&
	            reply->type == REDIS_REPLY_INTEGER &&
	            reply->integer == ENDIAN);
	freeReplyObject(reply);
	return res;
}

bool rdb_ping(redisContext *rdb)
{
	if (rdb == NULL) {
		return false;
	}

	if (redisAppendCommand(rdb, "PING") != REDIS_OK) {
		return false;
	}

	int done = 0;
	while (!done) {
		if (redisBufferWrite(rdb, &done) != REDIS_OK) {
			return false;
		}
	}

	struct pollfd pfd = { .fd = rdb->fd, .events = POLLIN };
	if (poll(&pfd, 1, 500) == 0) {
		return false;
	}

	redisReply *reply;
	if (redisGetReply(rdb, (void **)&reply) != REDIS_OK) {
		return false;
	}

	bool res = reply->type == REDIS_REPLY_STATUS &&
	           strcmp(reply->str, "PONG") == 0;

	freeReplyObject(reply);

	return res;
}

int rdb_role(redisContext *rdb)
{
	if (rdb == NULL) {
		return -1;
	}

	if (redisAppendCommand(rdb, "ROLE") != REDIS_OK) {
		return -1;
	}

	int done = 0;
	while (!done) {
		if (redisBufferWrite(rdb, &done) != REDIS_OK) {
			return -1;
		}
	}

	struct pollfd pfd = { .fd = rdb->fd, .events = POLLIN };
	if (poll(&pfd, 1, 1000) == 0) {
		return -1;
	}

	redisReply *reply;
	if (redisGetReply(rdb, (void **)&reply) != REDIS_OK) {
		return -1;
	}

	int res = -1;
	if (reply->type == REDIS_REPLY_ARRAY) {
		if (strcmp(reply->element[0]->str, "master") == 0) {
			res = 0;
		} else if (strcmp(reply->element[0]->str, "sentinel") == 0) {
			res = 2;
		} else {
			res = 1;
		}
	}

	freeReplyObject(reply);

	return res;
}

#else // ENABLE_REDIS

bool rdb_compatible(redisContext *rdb)
{
	return false;
}

bool rdb_ping(redisContext *rdb)
{
	return false;
}

int rdb_role(redisContext *rdb)
{
	return -1;
}

#endif // ENABLE_REDIS
