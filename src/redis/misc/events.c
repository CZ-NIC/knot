// gcc -g events.c -lhiredis

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hiredis/hiredis.h>

int main(int argv, char** args)
{
	redisContext *ctx = redisConnect("127.0.0.1", 6379);

	if (ctx->err) {
		/* Let context leak for now... */
		printf("Error: %s\n", ctx->errstr);
		return 1;
	}

	uint8_t stream[] = {'\x00', '\x02', 'n', 'u', '\x00'};
	char begin[128] = { '$', '\x00'};
	redisReply *reply;
	// BLOCK 0 means block indefinetly, use time in ms (milliseconds)
	while(reply = redisCommand(ctx,"XREAD BLOCK 0 STREAMS %b %s", stream, sizeof(stream), begin)) {
		if (reply == NULL){
			printf("Response not recev");
			return -1;
		}
		if(reply->type != REDIS_REPLY_ARRAY) {
			printf("Wrong format");
			return -1;
		}

		for (int stream_idx = 0; stream_idx < reply->elements; ++stream_idx) {
			redisReply *origin = reply->element[stream_idx]->element[0];
			redisReply *events = reply->element[stream_idx]->element[1];
			printf("%s\n---\n", origin->str + 1);
			for (int event_idx = 0; event_idx < events->elements; ++event_idx) {
				redisReply *timestamp = events->element[event_idx]->element[0];
				redisReply *data = events->element[event_idx]->element[1];
				//TODO assert data->elements >= 4
				memcpy(begin, timestamp->str, strlen(timestamp->str));
				printf("%s: %s\n%s: %s\n\n",
				       data->element[0]->str,
				       data->element[1]->str,
				       data->element[2]->str,
				       data->element[3]->str);
			}
		}
		freeReplyObject(reply);
	}

	return 0;
}