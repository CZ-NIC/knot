#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "knot/conf/conf.h"
#include "knot/common.h"

static const char *DEFAULT_CONFIG_1 = "/." PROJECT_EXEC "/" PROJECT_EXEC \
                                      ".conf";
static const char *DEFAULT_CONFIG_2 = "/etc/" PROJECT_EXEC "/" PROJECT_EXEC \
                                      ".conf";

/* Utilities. */
static char* strcdup(const char *s1, const char *s2)
{
	size_t slen = strlen(s1);
	size_t nlen = slen + strlen(s2) + 1;
	char* dst = malloc(nlen);
	memcpy(dst, s1, slen);
	strcpy(dst + slen, s2); // With trailing '\0'
	return dst;
}

static int rmkdir(char *path, int mode)
{
	char *p = path;
	while((p = strchr(p + 1, '/'))) {
		*p = '\0';
		mkdir(path, mode);
		*p = '/';
	}

	// Final path
	return mkdir(path, mode);
}

/* Prototypes for cf-parse.y */
extern char* yytext;
extern int yylineno;
extern int cf_parse();
conf_t *new_config;

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
	log_server_error("config: '%s' - %s on line %d (current token '%s').\n",
	                 new_config->filename, msg, yylineno, yytext);

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
	free(iface);
}

static void log_free(conf_log_t *log)
{
	if (!log) {
		return;
	}

	if (log->file) {
		free(log->file);
	}

	/* Free loglevel mapping. */
	node *n = 0, *nxt = 0;
	WALK_LIST_DELSAFE(n, nxt, log->map) {
		free((conf_log_map_t*)n);
	}

	free(log);
}

static void zone_free(conf_zone_t *zone)
{
	if (!zone) {
		return;
	}

	free(zone->name);
	free(zone->file);
	free(zone->db);
}

/* Config processing. */

static int conf_process(conf_t *conf)
{
	// Normalize paths
	conf->storage = strcpath(conf->storage);
	struct stat st;
	if (stat(conf->storage, &st) != 0) {
		rmkdir(conf->storage, S_IRWXU);
	}

	// Create PID file
	conf->pidfile = strcdup(conf->storage, "/" PID_FILE);

	// Postprocess zones
	node *n = 0;
	WALK_LIST (n, conf->zones) {
		conf_zone_t *zone = (conf_zone_t*)n;

		// Normalize zone filename
		zone->file = strcpath(zone->file);

		// Create zone db filename
		size_t stor_len = strlen(conf->storage);
		size_t size = stor_len + strlen(zone->name) + 4; // db/,\0
		char *dest = malloc(size);
		strcpy(dest, conf->storage);
		if (conf->storage[stor_len - 1] != '/') {
			strcat(dest, "/");
		}

		strcat(dest, zone->name);
		strcat(dest, "db");
		zone->db = dest;
	}

	/* Update hooks */
	/*! \todo Selective hooks. */
	conf->_touched = CONF_ALL;
	WALK_LIST (n, conf->hooks) {
		conf_hook_t *hook = (conf_hook_t*)n;
		if ((hook->sections & conf->_touched) && hook->update) {
			hook->update(conf);
		}
	}

	return 0;
}

/* Singleton config. */
conf_t *s_config = 0;

void __attribute__ ((constructor)) conf_init()
{
	// Create new config
	s_config = conf_new(0);

	/* Create default interface. */
	conf_iface_t * iface = malloc(sizeof(conf_iface_t));
	iface->name = strdup("any");
	iface->address = strdup("0.0.0.0");
	iface->port = CONFIG_DEFAULT_PORT;
	add_tail(&s_config->ifaces, &iface->n);
	++s_config->ifaces_count;

	/* Create default storage. */
	s_config->storage = strdup("/var/lib/"PROJECT_EXEC);

	/* Create default logs. */

	/* Syslog */
	conf_log_t *log = malloc(sizeof(conf_log_t));
	log->type = LOGT_SYSLOG;
	log->file = 0;
	init_list(&log->map);

	conf_log_map_t *map = malloc(sizeof(conf_log_map_t));
	map->source = LOG_ANY;
	map->prios = LOG_MASK(LOG_WARNING)|LOG_MASK(LOG_ERR);
	add_tail(&log->map, &map->n);
	add_tail(&s_config->logs, &log->n);
	++s_config->logs_count;

	/* Stderr */
	log = malloc(sizeof(conf_log_t));
	log->type = LOGT_STDERR;
	log->file = 0;
	init_list(&log->map);

	map = malloc(sizeof(conf_log_map_t));
	map->source = LOG_ANY;
	map->prios = LOG_MASK(LOG_WARNING)|LOG_MASK(LOG_ERR);
	add_tail(&log->map, &map->n);
	add_tail(&s_config->logs, &log->n);
	++s_config->logs_count;

	/* Process config. */
	conf_process(s_config);
}

void __attribute__ ((destructor)) conf_deinit()
{
	if (s_config) {
		conf_free(s_config);
		s_config = 0;
	}
}

/* API functions. */

conf_t *conf_new(const char* path)
{
	conf_t *c = malloc(sizeof(conf_t));
	memset(c, 0, sizeof(conf_t));

	// Add path
	if (path) {
		c->filename = strdup(path);
	}

	// Initialize lists
	init_list(&c->logs);
	init_list(&c->ifaces);
	init_list(&c->zones);
	init_list(&c->hooks);

	return c;
}

int conf_add_hook(conf_t * conf, int sections, int (*on_update)())
{
	conf_hook_t *hook = malloc(sizeof(conf_hook_t));
	hook->sections = sections;
	hook->update = on_update;
	add_tail(&conf->hooks, &hook->n);
	++conf->hooks_count;

	return 0;
}

int conf_parse(conf_t *conf)
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

	// Postprocess config
	conf_process(conf);

	return ret;
}

int conf_parse_str(conf_t *conf, const char* src)
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
	char *oldfn = new_config->filename;
	new_config->filename = "(stdin)";
	cf_parse();
	new_config->filename = oldfn;
	ret = _parser_res;
	_parser_src = 0;
	_parser_remaining = -1;
	// }
	pthread_mutex_unlock(&_parser_lock);

	// Postprocess config
	conf_process(conf);

	return ret;
}

void conf_truncate(conf_t *conf, int unload_hooks)
{
	if (!conf) {
		return;
	}

	node *n = 0, *nxt = 0;

	// Unload hooks
	if (unload_hooks) {
		WALK_LIST_DELSAFE(n, nxt, conf->hooks) {
			//! \todo call hook unload.
			free((conf_hook_t*)n);
		}
		conf->hooks_count = 0;
		init_list(&conf->hooks);
	}

	// Free key
	if (conf->key.secret) {
		free(conf->key.secret);
	}
	memset(&conf->key, 0, sizeof(conf_key_t));

	// Free interfaces
	WALK_LIST_DELSAFE(n, nxt, conf->ifaces) {
		iface_free((conf_iface_t*)n);
	}
	conf->ifaces_count = 0;
	init_list(&conf->ifaces);

	// Free logs
	WALK_LIST_DELSAFE(n, nxt, conf->logs) {
		log_free((conf_log_t*)n);
	}
	conf->logs_count = 0;
	init_list(&conf->logs);

	// Free zones
	WALK_LIST_DELSAFE(n, nxt, conf->zones) {
		zone_free((conf_zone_t*)n);
	}
	conf->zones_count = 0;
	init_list(&conf->zones);

	if (conf->filename) {
		free(conf->filename);
		conf->filename = 0;
	}
	if (conf->identity) {
		free(conf->identity);
		conf->identity = 0;
	}
	if (conf->version) {
		free(conf->version);
		conf->version = 0;
	}
	if (conf->storage) {
		free(conf->storage);
		conf->storage = 0;
	}
	if (conf->pidfile) {
		free(conf->pidfile);
		conf->pidfile = 0;
	}
}

void conf_free(conf_t *conf)
{
	if (!conf) {
		return;
	}

	// Truncate config
	conf_truncate(conf, 1);

	// Free config
	free(conf);
}

char* conf_find_default()
{
	/* Try DEFAULT_CONFIG_1 first. */
	const char *dir = getenv("HOME");
	const char *name = DEFAULT_CONFIG_1;
	char *path = strcdup(dir, name);
	struct stat st;
	if (stat(path, &st) != 0) {
		const char* fallback_path = DEFAULT_CONFIG_2;
		log_server_error("config: Trying '%s' as default configuration.\n",
		                 path);
		free(path);

		/* Try DEFAULT_CONFIG_2 as a fallback. */
		path = strdup(fallback_path);
	}

	log_server_error("config: Using '%s' as default configuration.\n",
	                path);
	return path;
}

int conf_open(const char* path)
{
	// Check existing config
	if (!s_config) {
		errno = ENOLINK; /* Link has been severed (POSIX.1) */
		return -1;
	}

	// Check path
	if (!path) {
		errno = ENOENT; /* No such file or directory (POSIX.1) */
		return -2;
	}

	// Check if exists
	struct stat st;
	if (stat(path, &st) != 0) {
		errno = ENOENT; /* No such file or directory (POSIX.1) */
		return -2;
	}

	// Truncate config
	conf_truncate(s_config, 0);

	// Parse config
	s_config->filename = strdup(path);
	int ret = conf_parse(s_config);
	if (ret != 0) {
		conf_free(s_config);
		s_config = 0;
		return ret;
	}

	return 0;
}

char* strcpath(char *path)
{
	// Remote trailing slash
	size_t plen = strlen(path);
	if (path[plen - 1] == '/') {
		path[--plen] = '\0';
	}

	// Expand '~'
	char* tild_p = strchr(path,'~');
	if (tild_p != 0) {
		// Get full path
		char *tild_exp = getenv("HOME");
		size_t tild_len = strlen(tild_exp);
		if (tild_exp[tild_len - 1] == '/') {
			tild_exp[--tild_len] = '\0';
		}

		// Expand
		char *npath = malloc(plen + tild_len + 1);
		npath[0] = '\0';
		strncpy(npath, path, (size_t)(tild_p - path));
		strcat(npath, tild_exp);
		strcat(npath, tild_p + 1);
		free(path);
		path = npath;
	}

	return path;
}

