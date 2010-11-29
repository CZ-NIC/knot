#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>

#include "conf.h"

static jmp_buf conf_jmpbuf;

struct config *new_config;

struct config *config_alloc(char *name)
{
	struct config *c = malloc(sizeof(struct config));
	c->filename = strdup(name);
	return c;
}

int config_parse(struct config *c)
{
	if (setjmp(conf_jmpbuf))
		return 1;

	new_config = c;
	cf_parse();
	return 0;
}

void cf_error(char *msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	longjmp(conf_jmpbuf, 1);
}
