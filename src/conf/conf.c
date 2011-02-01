#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>

#include "conf.h"

/* Prevent warnings from -Wmissing-prototypes.  */
extern int cf_parse();
static jmp_buf conf_jmpbuf;
config_t *new_config;

config_t *config_new(const char* path)
{
	config_t *c = malloc(sizeof(config_t));
	if (path) {
		c->filename = strdup(path);
	} else {
		c->filename = strdup(CONFIG_DEFAULT_PATH);
	}

	return c;
}

int config_parse(config_t *conf)
{
	if (setjmp(conf_jmpbuf)) {
		return 1;
	}

	new_config = conf;
	cf_parse();
	return 0;
}

void cf_error(char *msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	longjmp(conf_jmpbuf, 1);
}

void config_free(config_t *conf)
{
	if (conf) {
		free(conf->filename);
		free(conf);
	}
}
