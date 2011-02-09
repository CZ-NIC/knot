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

/* Parser instance globals. */
static volatile int _parser_res = 0;
static void *_parser_src = 0;
static ssize_t _parser_remaining = -1;
static pthread_mutex_t _parser_lock = PTHREAD_MUTEX_INITIALIZER;
int (*cf_read_hook)(char *buf, size_t nbytes) = 0;

/* Config file read hook. */
int cf_read_file(char *buf, size_t nbytes) {
	if (_parser_src == 0) {
		return -1;
	}

	// Read a maximum of nbytes
	return fread(buf, 1, nbytes, (FILE*)_parser_src);
}

/* Config file read hook - memory. */
int cf_read_mem(char *buf, size_t nbytes) {
	if (_parser_src == 0 || _parser_remaining < 0) {
		return -1;
	}

	// Assert remaining bytes
	if ((size_t)_parser_remaining < nbytes) {
		nbytes = (size_t)_parser_remaining;
	}

	// Check remaining
	if (nbytes == 0) {
		return 0;
	}

	// Read a maximum of nbytes
	void* dst = memcpy(buf, (const char*)_parser_src, nbytes);
	if (dst != 0) {
		_parser_remaining -= nbytes;
		_parser_src = (char*)_parser_src + nbytes;
		return nbytes;
	}

	return -1;
}

/* Config error report. */
void cf_error(const char *msg)
{
	log_error("Config parser error: %s\n", msg);
	_parser_res = -1;
}

/* Private helper functions. */
static void iface_free(conf_iface_t *iface)
{
	if (!iface) {
		return;
	}

	free(iface->name);
	free(iface->address);
	free(iface->sa);
	free(iface);
}

static void log_free(conf_log_t *log)
{
	if (!log) {
		return;
	}

	free(log->log_output);
	free(log);
}

static void zone_free(conf_zone_t *zone)
{
	if (!zone) {
		return;
	}

	free(zone->name);
	free(zone->file);
	//! \todo Free zone lists.
}

config_t *config_new(const char* path)
{
	config_t *c = malloc(sizeof(config_t));
	memset(c, 0, sizeof(config_t));

	// Add path
	if (path) {
		c->filename = strdup(path);
	} else {
		c->filename = strdup(CONFIG_DEFAULT_PATH);
	}

	// Initialize lists
	init_list(&c->logs);
	init_list(&c->ifaces);
	init_list(&c->zones);

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
	_parser_src = fopen(conf->filename, "r");
	_parser_remaining = -1;
	if (_parser_src == 0) {
		pthread_mutex_unlock(&_parser_lock);
		return -2;
	}

	// Parse config
	_parser_res = 0;
	cf_read_hook = cf_read_file;
	cf_parse();
	ret = _parser_res;
	fclose((FILE*)_parser_src);
	_parser_src = 0;
	// }
	pthread_mutex_unlock(&_parser_lock);

	return ret;
}

int config_parse_str(config_t *conf, const char* src)
{
	if (!src) {
		return -1;
	}

	int ret = 0;
	pthread_mutex_lock(&_parser_lock);
	// {
	// Hook new configuration
	new_config = conf;
	_parser_src = (char*)src;
	_parser_remaining = strlen(src);
	if (_parser_src == 0) {
		_parser_src = 0;
		_parser_remaining = -1;
		pthread_mutex_unlock(&_parser_lock);
		return -2;
	}

	// Parse config
	_parser_res = 0;
	cf_read_hook = cf_read_mem;
	cf_parse();
	ret = _parser_res;
	_parser_src = 0;
	_parser_remaining = -1;
	// }
	pthread_mutex_unlock(&_parser_lock);

	return ret;
}

void config_free(config_t *conf)
{
	if (!conf) {
		return;
	}

	// Free interfaces
	struct node *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, conf->ifaces) {
		iface_free((conf_iface_t*)n);
	}

	// Free keys
	if (conf->key.secret) {
		free(conf->key.secret);
	}

	// Free logs
	WALK_LIST_DELSAFE(n, nxt, conf->logs) {
		log_free((conf_log_t*)n);
	}

	// Free zones
	WALK_LIST_DELSAFE(n, nxt, conf->zones) {
		zone_free((conf_zone_t*)n);
	}

	free(conf->filename);
	free(conf->identity);
	free(conf->version);
	free(conf->storage);
	free(conf);
}

int config_open(const char* path)
{
	s_config = config_new(path);
	if (!s_config) {
		return -1;
	}
	if (config_parse(s_config) != 0) {
		config_free(s_config);
		s_config = 0;
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
