#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <urcu.h>
#include "knot/conf/conf.h"
#include "knot/common.h"
#include "knot/other/error.h"

/*
 * Defaults.
 */

#define DEFAULT_CONF_COUNT 2 /*!< \brief Number of default config paths. */

/*! \brief Default config paths. */
static const char *DEFAULT_CONFIG[2] = {
        "~/." PROJECT_EXEC "/" PROJECT_EXEC ".conf",
        "/etc/" PROJECT_EXEC "/" PROJECT_EXEC ".conf"
};

/*
 * Utilities.
 */

/*!
 * \brief Create new string from a concatenation of s1 and s2.
 * \param s1 First string.
 * \param s2 Second string.
 * \retval Newly allocated string on success.
 * \retval NULL on error.
 */
static char* strcdup(const char *s1, const char *s2)
{
	size_t slen = strlen(s1);
	size_t nlen = slen + strlen(s2) + 1;
	char* dst = malloc(nlen);
	if (!dst) {
		return 0;
	}

	memcpy(dst, s1, slen);
	strcpy(dst + slen, s2); // With trailing '\0'
	return dst;
}

/*!
 * \brief Recursively create directories.
 *
 * Similar to "mkdir -p".
 *
 * \retval 0 on success.
 * \retval <0 on error.
 */
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

/*
 * Parser instance globals.
 * \todo: Use pure reentrant parser to get rid of the globals.
 */
conf_t *new_config = 0; /*!< \brief Currently parsed config. */
static volatile int _parser_res = 0; /*!< \brief Parser result. */
static void *_parser_src = 0; /*!< \brief Parser data source. */
static ssize_t _parser_remaining = -1; /*!< \brief Parser remaining bytes. */
static pthread_mutex_t _parser_lock = PTHREAD_MUTEX_INITIALIZER;
int (*cf_read_hook)(char *buf, size_t nbytes) = 0;

/*!
 * \brief Config file read hook.
 *
 * Wrapper for fread().
 *
 * \retval number of read bytes on success.
 * \retval <0 on error.
 */
int cf_read_file(char *buf, size_t nbytes) {
	if (_parser_src == 0) {
		return -1;
	}

	// Read a maximum of nbytes
	return fread(buf, 1, nbytes, (FILE*)_parser_src);
}

/*!
 * \brief Config file read hook (from memory).
 * \retval number of read bytes on success.
 * \retval <0 on error.
 */
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

/*! \brief Config error report. */
void cf_error(const char *msg)
{
	log_server_error("Config '%s' - %s on line %d (current token '%s').\n",
	                 new_config->filename, msg, yylineno, yytext);

	_parser_res = -1;
}

/*
 * Config helper functions.
 */

/*! \brief Free config interfaces. */
static void iface_free(conf_iface_t *iface)
{
	if (!iface) {
		return;
	}

	free(iface->name);
	free(iface->address);
	free(iface);
}

/*! \brief Free config logs. */
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

/*! \brief Free config zones. */
static void zone_free(conf_zone_t *zone)
{
	if (!zone) {
		return;
	}

	free(zone->name);
	free(zone->file);
	free(zone->db);
}

/*!
 * \brief Call config hooks that need updating.
 *
 * This function is called automatically after config update.
 *
 * \todo Selective hooks.
 */
static void conf_update_hooks(conf_t *conf)
{
	node *n = 0;
	conf->_touched = CONF_ALL;
	WALK_LIST (n, conf->hooks) {
		conf_hook_t *hook = (conf_hook_t*)n;
		if ((hook->sections & conf->_touched) && hook->update) {
			hook->update(conf, hook->data);
		}
	}
}

/*!
 * \brief Process parsed configuration.
 *
 * This functions is called automatically after config parsing.
 * It is needed to setup needed primitives, check and update paths.
 *
 * \retval 0 on success.
 * \retval <0 on error.
 */
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

	return 0;
}

/*
 * Singletion configuration API.
 */

conf_t *s_config = 0; /*! \brief Singleton config instance. */

/*! \brief Singleton config constructor (automatically called on load). */
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

/*! \brief Singleton config destructor (automatically called on exit). */
void __attribute__ ((destructor)) conf_deinit()
{
	if (s_config) {
		conf_free(s_config);
		s_config = 0;
	}
}

/*!
 * \brief Parse config (from file).
 * \return yyparser return value.
 */
static int conf_fparser(conf_t *conf)
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

/*! \brief Parse config (from string).
 * \return yyparser return value.
 */
static int conf_strparser(conf_t *conf, const char *src)
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
	return ret;
}

/*
 * API functions.
 */

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

int conf_add_hook(conf_t * conf, int sections,
                  int (*on_update)(const conf_t*, void*), void *data)
{
	conf_hook_t *hook = malloc(sizeof(conf_hook_t));
	if (!hook) {
		return KNOT_ENOMEM;
	}

	hook->sections = sections;
	hook->update = on_update;
	hook->data = data;
	add_tail(&conf->hooks, &hook->n);
	++conf->hooks_count;

	return KNOT_EOK;
}

int conf_parse(conf_t *conf)
{
	/* Parse file. */
	int ret = conf_fparser(conf);

	/* Postprocess config. */
	conf_process(conf);

	/* Update hooks. */
	conf_update_hooks(conf);

	if (ret < 0) {
		return KNOT_EPARSEFAIL;
	}

	return KNOT_EOK;
}

int conf_parse_str(conf_t *conf, const char* src)
{
	/* Parse config from string. */
	int ret = conf_strparser(conf, src);

	/* Postprocess config. */
	conf_process(conf);

	/* Update hooks */
	conf_update_hooks(conf);

	if (ret < 0) {
		return KNOT_EPARSEFAIL;
	}

	return KNOT_EOK;
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
	/* Try sequentially each default path. */
	char *path = 0;
	for (int i = 0; i < DEFAULT_CONF_COUNT; ++i) {
		path = strcpath(strdup(DEFAULT_CONFIG[i]));

		/* Break, if the path exists. */
		struct stat st;
		if (stat(path, &st) == 0) {
			break;
		}

		log_server_notice("Config '%s' does not exist.\n",
		                  path);

		/* Keep the last item. */
		if (i < DEFAULT_CONF_COUNT - 1) {
			free(path);
			path = 0;
		}
	}

	log_server_info("Using '%s' as default configuration.\n",
	                path);
	return path;
}

int conf_open(const char* path)
{
	/* Check path. */
	if (!path) {
		return KNOT_EINVAL;
	}

	/* Check if exists. */
	struct stat st;
	if (stat(path, &st) != 0) {
		return KNOT_ENOENT;
	}

	/* Create new config. */
	conf_t *nconf = conf_new(path);

	/* Parse config. */
	int ret = conf_fparser(nconf);
	if (ret != 0) {
		conf_free(nconf);
		return ret;
	}

	/* Replace current config. */
	conf_t *oldconf = rcu_xchg_pointer(&s_config, nconf);

	/* Copy hooks. */
	if (oldconf) {
		node *n = 0;
		WALK_LIST (n, oldconf->hooks) {
			conf_hook_t *hook = (conf_hook_t*)n;
			conf_add_hook(nconf, hook->sections,
			              hook->update, hook->data);
		}
	}

	/* Postprocess config. */
	conf_process(nconf);

	/* Synchronize. */
	synchronize_rcu();

	/* Free old config. */
	if (oldconf) {
		conf_free(oldconf);
	}

	/* Update hooks. */
	conf_update_hooks(nconf);

	return KNOT_EOK;
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

