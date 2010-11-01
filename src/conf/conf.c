
#include "conf.h"

struct config *
config_alloc(char *name)
{
	struct config *c = malloc(sizeof(struct config));
	c->filename = strdup(name);
	return c;
}

int
config_parse(struct config *c)
{

	
}
