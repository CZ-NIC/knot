/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

/*! \brief Default config paths. */
static const char *DEFAULT_CONFIG[] = {
	SYSCONFDIR "/" "knot.conf",
};

#define DEFAULT_CONF_COUNT 1 /*!< \brief Number of default config paths. */

/*
 * Utilities.
 */

/* Prototypes for cf-parse.y */
extern int cf_parse(void *scanner);
extern int cf_get_lineno(void *scanner);
extern char *cf_get_text(void *scanner);
extern int cf_lex_init(void *scanner);
extern void cf_set_in(FILE *f, void *scanner);
extern void cf_lex_destroy(void *scanner);
extern void switch_input(const char *str, void *scanner);

conf_t *new_config = 0; /*!< \brief Currently parsed config. */
static volatile int _parser_res = 0; /*!< \brief Parser result. */
static pthread_mutex_t _parser_lock = PTHREAD_MUTEX_INITIALIZER;

/*! \brief Config error report. */
void cf_error(void *scanner, const char *msg)
{
	int lineno = -1;
	char *text = "???";
	if (scanner) {
		lineno = cf_get_lineno(scanner);
		text = (char *)cf_get_text(scanner);
	}

	log_server_error("Config '%s' - %s on line %d (current token '%s').\n",
			 new_config->filename, msg, lineno, text);


	_parser_res = KNOTD_EPARSEFAIL;
}

/*
 * Config helper functions.
 */

/*! \brief Free TSIG key. */
static void key_free(conf_key_t *k)
{
	/* Secure erase. */
	if (k->k.secret) {
		memset(k->k.secret, 0, strlen(k->k.secret));
	}
	free(k->k.secret);
	knot_dname_free(&k->k.name);
	free(k);
}

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

	/* Free ACL lists. */
	WALK_LIST_FREE(zone->acl.xfr_in);
	WALK_LIST_FREE(zone->acl.xfr_out);
	WALK_LIST_FREE(zone->acl.notify_in);
	WALK_LIST_FREE(zone->acl.notify_out);

	free(zone->name);
	free(zone->file);
	free(zone->db);
	free(zone->ixfr_db);
	free(zone);
}

/*!
 * \brief Call config hooks that need updating.
 *
 * This function is called automatically after config update.
 *
 * \todo Selective hooks (issue #1583).
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
	// Check
	if (conf->storage == NULL) {
		conf->storage = strdup("/var/lib/"PROJECT_EXEC);
		if (conf->storage == NULL) {
			return KNOTD_ENOMEM;
		}
	}
	
	// Normalize paths
	conf->storage = strcpath(conf->storage);

	// Storage directory exists?
	struct stat st;
	if (stat(conf->storage, &st) == -1) {
		log_server_error("Could not open storage directory '%s'\n", conf->storage);
		// I assume that conf->* is freed elsewhere
		return KNOTD_EINVAL;
	}

	// Storage directory is a directory?
	if (S_ISDIR(st.st_mode) == 0) {
		log_server_error("Configured storage '%s' not a directory\n", conf->storage);
		return KNOTD_EINVAL;
	}

	// Create PID file
	if (conf->pidfile == NULL) {
		conf->pidfile = strcdup(conf->storage, "/" PID_FILE);
		if (conf->pidfile == NULL) {
			return KNOTD_ENOMEM;
		}
	}

	// Postprocess zones
	int ret = KNOTD_EOK;
	node *n = 0;
	WALK_LIST (n, conf->zones) {
		conf_zone_t *zone = (conf_zone_t*)n;

		// Default policy for dbsync timeout
		if (zone->dbsync_timeout < 0) {
			zone->dbsync_timeout = conf->dbsync_timeout;
		}

		// Default policy for semantic checks
		if (zone->enable_checks < 0) {
			zone->enable_checks = conf->zone_checks;
		}

		// Default policy for NOTIFY retries
		if (zone->notify_retries <= 0) {
			zone->notify_retries = conf->notify_retries;
		}

		// Default policy for NOTIFY timeout
		if (zone->notify_timeout <= 0) {
			zone->notify_timeout = conf->notify_timeout;
		}

		// Default policy for IXFR FSLIMIT
		if (zone->ixfr_fslimit == 0) {
			zone->ixfr_fslimit = conf->ixfr_fslimit;
		}

		// Normalize zone filename
		zone->file = strcpath(zone->file);
		if (zone->file == NULL) {
			zone->db = NULL;
			ret = KNOTD_ENOMEM;
			continue;
		}

		// Create zone db filename
		size_t zname_len = strlen(zone->name);
		size_t stor_len = strlen(conf->storage);
		size_t size = stor_len + zname_len + 4; // /db,\0
		char *dest = malloc(size);
		if (dest == NULL) {
			zone->db = NULL; /* Not enough memory. */
			ret = KNOTD_ENOMEM; /* Error report. */
			continue;
		}
		char *dpos = dest;
		
		/* Since we have already allocd dest to accomodate
		 * storage/zname length strcpy is safe. */
		memcpy(dpos, conf->storage, stor_len + 1);
		dpos += stor_len;
		if (*(dpos - 1) != '/') {
			*(dpos++) = '/';
			*dpos = '\0';
		}

		memcpy(dpos, zone->name, zname_len + 1);
		memcpy(dpos + zname_len, "db", 3);
		zone->db = dest;

		// Create IXFR db filename
		stor_len = strlen(conf->storage);
		size = stor_len + zname_len + 9; // /diff.db,\0
		dest = malloc(size);
		if (dest == NULL) {
			zone->ixfr_db = NULL; /* Not enough memory. */
			ret = KNOTD_ENOMEM; /* Error report. */
			continue;
		}
		strncpy(dest, conf->storage, stor_len + 1);
		if (conf->storage[stor_len - 1] != '/') {
			strncat(dest, "/", 1);
		}

		const char *dbext = "diff.db";
		strncat(dest, zone->name, zname_len);
		strncat(dest, dbext, strlen(dbext));
		zone->ixfr_db = dest;
	}

	return ret;
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
	memset(iface, 0, sizeof(conf_iface_t));
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
		return KNOTD_EINVAL;
	}

	int ret = KNOTD_EOK;
	pthread_mutex_lock(&_parser_lock);
	// {
	// Hook new configuration
	new_config = conf;
	FILE *f = fopen(conf->filename, "r");
	if (f == 0) {
		pthread_mutex_unlock(&_parser_lock);
		return KNOTD_ENOENT;
	}

	// Parse config
	_parser_res = KNOTD_EOK;
	new_config->filename = conf->filename;
	void *sc = NULL;
	cf_lex_init(&sc);
	cf_set_in(f, sc);
	cf_parse(sc);
	cf_lex_destroy(sc);
	ret = _parser_res;
	fclose(f);
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
		return KNOTD_EINVAL;
	}

	int ret = KNOTD_EOK;
	pthread_mutex_lock(&_parser_lock);
	// {
	// Hook new configuration
	new_config = conf;

	// Parse config
	_parser_res = KNOTD_EOK;
	char *oldfn = new_config->filename;
	new_config->filename = "(stdin)";
	void *sc = NULL;
	cf_lex_init(&sc);
	switch_input(src, sc);
	cf_parse(sc);
	cf_lex_destroy(sc);
	new_config->filename = oldfn;
	ret = _parser_res;
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
	init_list(&c->remotes);
	init_list(&c->keys);

	// Defaults
	c->zone_checks = 0;
	c->notify_retries = CONFIG_NOTIFY_RETRIES;
	c->notify_timeout = CONFIG_NOTIFY_TIMEOUT;
	c->dbsync_timeout = CONFIG_DBSYNC_TIMEOUT;
	c->ixfr_fslimit = -1;
	c->uid = -1;
	c->gid = -1;

	return c;
}

int conf_add_hook(conf_t * conf, int sections,
                  int (*on_update)(const conf_t*, void*), void *data)
{
	conf_hook_t *hook = malloc(sizeof(conf_hook_t));
	if (!hook) {
		return KNOTD_ENOMEM;
	}

	hook->sections = sections;
	hook->update = on_update;
	hook->data = data;
	add_tail(&conf->hooks, &hook->n);
	++conf->hooks_count;

	return KNOTD_EOK;
}

int conf_parse(conf_t *conf)
{
	/* Parse file. */
	int ret = conf_fparser(conf);

	/* Postprocess config. */
	if (ret == 0) {
		ret = conf_process(conf);
		/* Update hooks. */
		conf_update_hooks(conf);
	}

	if (ret < 0) {
		return KNOTD_EPARSEFAIL;
	}

	return KNOTD_EOK;
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
		return KNOTD_EPARSEFAIL;
	}

	return KNOTD_EOK;
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
			/*! \todo Call hook unload (issue #1583) */
			free((conf_hook_t*)n);
		}
		conf->hooks_count = 0;
		init_list(&conf->hooks);
	}

	// Free keys
	WALK_LIST_DELSAFE(n, nxt, conf->keys) {
		key_free((conf_key_t *)n);
	}

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

	// Free remotes
	WALK_LIST_DELSAFE(n, nxt, conf->remotes) {
		iface_free((conf_iface_t*)n);
	}
	conf->remotes_count = 0;
	init_list(&conf->remotes);

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
	if (conf->nsid) {
		free(conf->nsid);
		conf->nsid = 0;
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
		return KNOTD_EINVAL;
	}

	/* Check if exists. */
	struct stat st;
	if (stat(path, &st) != 0) {
		return KNOTD_ENOENT;
	}

	/* Create new config. */
	conf_t *nconf = conf_new(path);

	/* Parse config. */
	int ret = conf_fparser(nconf);
	if (ret == KNOTD_EOK) {
		/* Postprocess config. */
		ret = conf_process(nconf);
	}
	
	if (ret != KNOTD_EOK) {
		conf_free(nconf);
		return ret;
	}

	/* Replace current config. */
	conf_t *oldconf = rcu_xchg_pointer(&s_config, nconf);

	/* Copy hooks. */
	if (oldconf) {
		node *n = 0, *nxt = 0;
		WALK_LIST_DELSAFE (n, nxt, oldconf->hooks) {
			conf_hook_t *hook = (conf_hook_t*)n;
			conf_add_hook(nconf, hook->sections,
			              hook->update, hook->data);
		}
	}

	/* Synchronize. */
	synchronize_rcu();

	/* Free old config. */
	if (oldconf) {
		conf_free(oldconf);
	}

	/* Update hooks. */
	conf_update_hooks(nconf);

	return KNOTD_EOK;
}

char* strcdup(const char *s1, const char *s2)
{
	if (!s1 || !s2) {
		return NULL;
	}
	
	size_t slen = strlen(s1);
	size_t s2len = strlen(s2);
	size_t nlen = slen + s2len + 1;
	char* dst = malloc(nlen);
	if (dst == NULL) {
		return NULL;
	}

	memcpy(dst, s1, slen);
	strncpy(dst + slen, s2, s2len + 1); // With trailing '\0'
	return dst;
}

char* strcpath(char *path)
{
	// NULL path
	if (!path) {
		return NULL;
	}
	
	// Remote trailing slash
	size_t plen = strlen(path);
	if (path[plen - 1] == '/') {
		path[--plen] = '\0';
	}

	// Expand '~'
	char* remainder = strchr(path,'~');
	if (remainder != NULL) {
		if (remainder[1] != '/') {
			log_server_warning("Cannot expand non-login user home directory '%s', use full path instead", path);
		}

		// Get full path
		char *tild_exp_unsafe = getenv("HOME");
		if (tild_exp_unsafe == NULL) {
			return NULL;
		}
		// Sanitize
		size_t tild_len = strlen(tild_exp_unsafe);
		char *tild_exp = malloc(tild_len + 1);
		if (tild_exp == NULL) {
			return NULL;
		}
		// Duplicate tild_exp including terminating NULL
		memcpy(tild_exp, tild_exp_unsafe, tild_len + 1);
		if (tild_exp[tild_len - 1] == '/') {
			tild_exp[--tild_len] = '\0';
		}

		// Expand
		char *npath = malloc(plen + tild_len + 1);
		if (npath == NULL) {
			free(tild_exp);
			return NULL;
		}
		npath[0] = '\0';
		strncpy(npath, path, (size_t)(remainder - path));
		strncat(npath, tild_exp, tild_len);
		
		// Append remainder
		++remainder;
		strncat(npath, remainder, strlen(remainder));

		free(tild_exp);
		free(path);
		path = npath;
	}

	return path;
}

