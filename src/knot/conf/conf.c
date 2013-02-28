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
#include "knot/ctl/remote.h"

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


	_parser_res = KNOT_EPARSEFAIL;
}

static int conf_ztree_compare(void *p1, void *p2)
{
	return knot_dname_compare((knot_dname_t*)p1, (knot_dname_t*)p2);
}

static void conf_ztree_free(void *node, void *data)
{
	UNUSED(data);
	knot_dname_t *zname = (knot_dname_t*)node;
	knot_dname_free(&zname);
}

static void conf_parse_begin(conf_t *conf)
{
	conf->zone_tree = gen_tree_new(conf_ztree_compare);
}

static void conf_parse_end(conf_t *conf) 
{
	if (conf->zone_tree) {
		gen_tree_destroy(&conf->zone_tree, conf_ztree_free, NULL);
	}
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
			return KNOT_ENOMEM;
		}
	}
	
	// Normalize paths
	conf->storage = strcpath(conf->storage);

	// Storage directory exists?
	struct stat st;
	if (stat(conf->storage, &st) == -1) {
		log_server_error("Could not open storage directory '%s'\n", conf->storage);
		// I assume that conf->* is freed elsewhere
		return KNOT_EINVAL;
	}

	// Storage directory is a directory?
	if (S_ISDIR(st.st_mode) == 0) {
		log_server_error("Configured storage '%s' not a directory\n", conf->storage);
		return KNOT_EINVAL;
	}

	// Create PID file
	if (conf->pidfile == NULL) {
		conf->pidfile = strcdup(conf->storage, "/" PID_FILE);
		if (conf->pidfile == NULL) {
			return KNOT_ENOMEM;
		}
	}
	
	/* Default TCP/UDP limits. */
	if (conf->max_conn_idle < 1) {
		conf->max_conn_idle = CONFIG_IDLE_WD;
	}
	if (conf->max_conn_hs < 1) {
		conf->max_conn_hs = CONFIG_HANDSHAKE_WD;
	}
	if (conf->max_conn_reply < 1) {
		conf->max_conn_reply = CONFIG_REPLY_WD;
	}
	
	// Postprocess interfaces
	conf_iface_t *cfg_if = NULL;
	WALK_LIST(cfg_if, conf->ifaces) {
		if (cfg_if->port <= 0) {
			cfg_if->port = CONFIG_DEFAULT_PORT;
		}
	}
	if (conf->ctl.iface && conf->ctl.iface->port <= 0) {
		conf->ctl.iface->port = REMOTE_DPORT;
	}
	
	/* Default RRL limits. */
	if (conf->rrl_slip < 0) {
		conf->rrl_slip = CONFIG_RRL_SLIP;
	}
	if (conf->rrl_size == 0) {
		conf->rrl_size = CONFIG_RRL_SIZE;
	}

	// Postprocess zones
	int ret = KNOT_EOK;
	node *n = 0;
	WALK_LIST (n, conf->zones) {
		conf_zone_t *zone = (conf_zone_t*)n;

		// Default policy for dbsync timeout
		if (zone->dbsync_timeout < 0) {
			zone->dbsync_timeout = conf->dbsync_timeout;
		}
		
		// Default policy for ixfr-from-differences
		if (zone->build_diffs < 0) {
			zone->build_diffs = conf->build_diffs;
		}

		// Default policy for semantic checks
		if (zone->enable_checks < 0) {
			zone->enable_checks = conf->zone_checks;
		}
		
		// Default policy for disabling ANY type queries for AA
		if (zone->disable_any < 0) {
			zone->disable_any = conf->disable_any;
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
		
		// Default zone file
		if (zone->file == NULL) {
			zone->file = strcdup(zone->name, ".zone");
			if (!zone->file) {
				ret = KNOT_ENOMEM;
				continue;
			}
		}
		
		// Relative zone filenames should be relative to storage
		if (zone->file[0] != '/') {
			size_t prefix_len = strlen(conf->storage) + 1; // + '\0'
			size_t zp_len = strlen(zone->file) + 1;
			char *ap = malloc(prefix_len + zp_len);
			if (ap != NULL) {
				memcpy(ap, conf->storage, prefix_len);
				ap[prefix_len - 1] = '/';
				memcpy(ap + prefix_len, zone->file, zp_len);
				free(zone->file);
				zone->file = ap;
			} else {
				ret = KNOT_ENOMEM;
				continue;
			}
		}

		// Normalize zone filename
		zone->file = strcpath(zone->file);
		if (zone->file == NULL) {
			zone->db = NULL;
			ret = KNOT_ENOMEM;
			continue;
		}

		// Create zone db filename
		size_t zname_len = strlen(zone->name);
		size_t stor_len = strlen(conf->storage);
		size_t size = stor_len + zname_len + 4; // /db,\0
		char *dest = malloc(size);
		if (dest == NULL) {
			zone->db = NULL; /* Not enough memory. */
			ret = KNOT_ENOMEM; /* Error report. */
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

		/* Copy origin and remove bad characters. */
		memcpy(dpos, zone->name, zname_len + 1);
		for (int i = 0; i < zname_len; ++i) {
			if (dpos[i] == '/') dpos[i] = '_';
		}
		
		memcpy(dpos + zname_len, "db", 3);
		zone->db = dest;

		// Create IXFR db filename
		stor_len = strlen(conf->storage);
		size = stor_len + zname_len + 9; // /diff.db,\0
		dest = malloc(size);
		if (dest == NULL) {
			zone->ixfr_db = NULL; /* Not enough memory. */
			ret = KNOT_ENOMEM; /* Error report. */
			continue;
		}
		dpos = dest;
		memcpy(dpos, conf->storage, stor_len + 1);
		dpos += stor_len;
		if (conf->storage[stor_len - 1] != '/') {
			*(dpos++) = '/';	
			*dpos = '\0';
		}

		const char *dbext = "diff.db";
		memcpy(dpos, zone->name, zname_len + 1);
		for (int i = 0; i < zname_len; ++i) {
			if (dpos[i] == '/') dpos[i] = '_';
		}
		memcpy(dpos + zname_len, dbext, strlen(dbext) + 1);
		zone->ixfr_db = dest;
	}
	
	/* Update UID and GID. */
	if (conf->uid < 0) conf->uid = getuid();
	if (conf->gid < 0) conf->gid = getgid();
	
	/* Build remote control ACL. */
	sockaddr_t addr;
	conf_remote_t *r = NULL;
	WALK_LIST(r, conf->ctl.allow) {
		conf_iface_t *i = r->remote;
		sockaddr_init(&addr, -1);
		sockaddr_set(&addr, i->family, i->address, 0);
		sockaddr_setprefix(&addr, i->prefix);
		acl_create(conf->ctl.acl, &addr, ACL_ACCEPT, i, 0);
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
	if (!s_config) {
		return;
	}

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
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	pthread_mutex_lock(&_parser_lock);
	
	// {
	// Hook new configuration
	new_config = conf;
	FILE *f = fopen(conf->filename, "r");
	if (f == 0) {
		pthread_mutex_unlock(&_parser_lock);
		return KNOT_ENOENT;
	}

	// Parse config
	_parser_res = KNOT_EOK;
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
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	pthread_mutex_lock(&_parser_lock);
	// {
	// Hook new configuration
	new_config = conf;

	// Parse config
	_parser_res = KNOT_EOK;
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

	/* Add path. */
	if (path) {
		c->filename = strdup(path);
	}

	/* Initialize lists. */
	init_list(&c->logs);
	init_list(&c->ifaces);
	init_list(&c->zones);
	init_list(&c->hooks);
	init_list(&c->remotes);
	init_list(&c->keys);
	init_list(&c->ctl.allow);

	/* Defaults. */
	c->zone_checks = 0;
	c->notify_retries = CONFIG_NOTIFY_RETRIES;
	c->notify_timeout = CONFIG_NOTIFY_TIMEOUT;
	c->dbsync_timeout = CONFIG_DBSYNC_TIMEOUT;
	c->ixfr_fslimit = -1;
	c->uid = -1;
	c->gid = -1;
	c->build_diffs = 0; /* Disable by default. */
	
	/* ACLs. */
	c->ctl.acl = acl_new(ACL_DENY, "remote_ctl");
	if (!c->ctl.acl) {
		free(c->filename);
		free(c);
		c = NULL;
	}

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
	conf_parse_begin(conf);
	int ret = conf_fparser(conf);
	conf_parse_end(conf);
	
	/* Postprocess config. */
	if (ret == 0) {
		ret = conf_process(conf);
		/* Update hooks. */
		conf_update_hooks(conf);
	}

	if (ret < 0) {
		return KNOT_EPARSEFAIL;
	}

	return KNOT_EOK;
}

int conf_parse_str(conf_t *conf, const char* src)
{
	/* Parse config from string. */
	conf_parse_begin(conf);
	int ret = conf_strparser(conf, src);
	conf_parse_end(conf);

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
			/*! \todo Call hook unload (issue #1583) */
			free((conf_hook_t*)n);
		}
		conf->hooks_count = 0;
		init_list(&conf->hooks);
	}

	// Free keys
	WALK_LIST_DELSAFE(n, nxt, conf->keys) {
		conf_free_key((conf_key_t *)n);
	}

	// Free interfaces
	WALK_LIST_DELSAFE(n, nxt, conf->ifaces) {
		conf_free_iface((conf_iface_t*)n);
	}
	conf->ifaces_count = 0;
	init_list(&conf->ifaces);

	// Free logs
	WALK_LIST_DELSAFE(n, nxt, conf->logs) {
		conf_free_log((conf_log_t*)n);
	}
	conf->logs_count = 0;
	init_list(&conf->logs);

	// Free remote interfaces
	WALK_LIST_DELSAFE(n, nxt, conf->remotes) {
		conf_free_iface((conf_iface_t*)n);
	}
	conf->remotes_count = 0;
	init_list(&conf->remotes);

	// Free zones
	WALK_LIST_DELSAFE(n, nxt, conf->zones) {
		conf_free_zone((conf_zone_t*)n);
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
	
	/* Free remote control list. */
	WALK_LIST_DELSAFE(n, nxt, conf->ctl.allow) {
		conf_free_remote((conf_remote_t*)n);
	}
	conf->remotes_count = 0;
	init_list(&conf->remotes);
	
	/* Free remote control ACL. */
	acl_truncate(conf->ctl.acl);
	
	/* Free remote control iface. */
	conf_free_iface(conf->ctl.iface);
}

void conf_free(conf_t *conf)
{
	if (!conf) {
		return;
	}

	/* Truncate config. */
	conf_truncate(conf, 1);
	
	/* Free remote control ACL. */
	acl_delete(&conf->ctl.acl);

	/* Free config. */
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
	if (!nconf) {
		return KNOT_ENOMEM;
	}

	/* Parse config. */
	conf_parse_begin(nconf);
	int ret = conf_fparser(nconf);
	conf_parse_end(nconf);
	if (ret == KNOT_EOK) {
		/* Postprocess config. */
		ret = conf_process(nconf);
	}
	
	if (ret != KNOT_EOK) {
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

	return KNOT_EOK;
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

void conf_free_zone(conf_zone_t *zone)
{
	if (!zone) {
		return;
	}

	/* Free ACL lists. */
	WALK_LIST_FREE(zone->acl.xfr_in);
	WALK_LIST_FREE(zone->acl.xfr_out);
	WALK_LIST_FREE(zone->acl.notify_in);
	WALK_LIST_FREE(zone->acl.notify_out);
	WALK_LIST_FREE(zone->acl.update_in);

	free(zone->name);
	free(zone->file);
	free(zone->db);
	free(zone->ixfr_db);
	free(zone);
}

void conf_free_key(conf_key_t *k)
{
	/* Secure erase. */
	if (k->k.secret) {
		memset(k->k.secret, 0, strlen(k->k.secret));
	}
	free(k->k.secret);
	knot_dname_free(&k->k.name);
	free(k);
}

void conf_free_iface(conf_iface_t *iface)
{
	if (!iface) {
		return;
	}

	free(iface->name);
	free(iface->address);
	free(iface);
}

void conf_free_remote(conf_remote_t *r)
{
	free(r);
}

void conf_free_log(conf_log_t *log)
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

