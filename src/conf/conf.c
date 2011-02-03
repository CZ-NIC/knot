#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "conf.h"
#include "common.h"

/* Prototypes for cf-parse.y */
extern int cf_parse();
config_t *new_config;

/* Singleton config. */
static config_t *s_config = 0;

/* Config parser lock. */
static volatile int _parser_res = 0;
static FILE* _parser_fp = 0;
static pthread_mutex_t _parser_lock = PTHREAD_MUTEX_INITIALIZER;

/* Config file read hook. */
int cf_read_hook(char *buf, size_t nbytes) {
	if (_parser_fp == 0) {
		return -1;
	}

	// Read a maximum of nbytes
	return fread(buf, 1, nbytes, _parser_fp);
}

/* Config error report. */
void cf_error(const char *msg)
{
	log_error("Config parser error: %s\n", msg);
	_parser_res = -1;
}

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
	if (!conf->filename) {
		return -1;
	}

	int ret = 0;
	pthread_mutex_lock(&_parser_lock);
	// {
	// Hook new configuration
	new_config = conf;
	_parser_fp = fopen(conf->filename, "r");
	if (_parser_fp == 0) {
		pthread_mutex_unlock(&_parser_lock);
		return -2;
	}

	// Parse config
	_parser_res = 0;
	cf_parse();
	ret = _parser_res;
	// }
	pthread_mutex_unlock(&_parser_lock);

	fclose(_parser_fp);
	_parser_fp = 0;

	return ret;
}

void config_free(config_t *conf)
{
	if (conf) {
		free(conf->filename);
		free(conf);
	}
}

int config_open(const char* path)
{
	s_config = config_new(path);
	if (!s_config) {
		return -1;
	}
	if (config_parse(s_config) != 0) {
		config_free(s_config);
		return -1;
	}

	return 0;
}

const config_t* config_get()
{
	return s_config;
}

int config_close()
{
	if (!s_config) {
		return -1;
	}

	config_free(s_config);
	s_config = 0;
	return 0;
}
