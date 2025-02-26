// gcc -g events.c -lhiredis

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hiredis/hiredis.h>

static void subCallback(redisContext *c, void *r, void *privdata)
{
	redisReply *reply = (redisReply*)r;
	if (reply == NULL){
		printf("Response not recev");
		return;
	}
	if(reply->type == REDIS_REPLY_ARRAY & reply->elements == 3) {
		if(strcmp( reply->element[0]->str,"subscribe") != 0) {
			printf("Message received -> %s%s %s%s\n", reply->element[2]->str, " (on channel :", reply->element[1]->str, ")");
		}
	}
}

int main(int argv, char** args)
{
	redisContext *ctx = redisConnect("127.0.0.1", 6379);

	if (ctx->err) {
		/* Let context leak for now... */
		printf("Error: %s\n", ctx->errstr);
		return 1;
	}

	redisReply *reply = redisCommand(ctx,"SUBSCRIBE knot.events");
	freeReplyObject(reply);
	while(1) {
		if (redisGetReply(ctx,(void *)&reply) != REDIS_OK) {
			continue;
		}
		subCallback(ctx, reply, NULL);
		freeReplyObject(reply);
	}

	return 0;
}