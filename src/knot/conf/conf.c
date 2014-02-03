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

#include <config.h>
#include <assert.h>
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
#include "knot/conf/extra.h"
#include "knot/knot.h"
#include "knot/ctl/remote.h"

/*
 * Defaults.
 */

/*! \brief Default config paths. */
static const char *DEFAULT_CONFIG[] = {
	CONFIG_DIR "/" "knot.conf",
};

#define DEFAULT_CONF_COUNT        1 /*!< \brief Number of default config paths. */
#define ERROR_BUFFER_SIZE       512 /*!< \brief Error buffer size. */

/*
 * Utilities.
 */

/* Prototypes for cf-parse.y */
extern int cf_parse(void *scanner);
extern int cf_get_lineno(void *scanner);
extern void cf_set_error(void *scanner);
extern char *cf_get_text(void *scanner);
extern conf_extra_t *cf_get_extra(void *scanner);
extern int cf_lex_init_extra(void *, void *scanner);
extern void cf_set_in(FILE *f, void *scanner);
extern void cf_lex_destroy(void *scanner);
extern void switch_input(const char *str, void *scanner);
extern char *cf_current_filename(void *scanner);

conf_t *new_config = NULL; /*!< \brief Currently parsed config. */
static volatile int _parser_res = 0; /*!< \brief Parser result. */
static pthread_mutex_t _parser_lock = PTHREAD_MUTEX_INITIALIZER;

static void cf_print_error(void *scanner, const char *msg)
{
	conf_extra_t *extra = NULL;
	int lineno = -1;
	char *text = "?";
	char *filename = NULL;
	conf_include_t *inc = NULL;

	if (scanner) {
		extra = cf_get_extra(scanner);
		lineno = cf_get_lineno(scanner);
		inc = conf_includes_top(extra->includes);
		extra->error = true;
	}

	if (extra && lineno != 0) {
		text = cf_get_text(scanner);
	}

	if (inc && inc->filename) {
		filename = inc->filename;
	} else {
		filename = new_config->filename;
	}

	log_server_error("Config error in '%s' (line %d token '%s') - %s\n",
			 filename, lineno, text, msg);

	_parser_res = KNOT_EPARSEFAIL;
}

/*! \brief Config error report. */
void cf_error(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, buffer);
}

static void conf_parse_begin(conf_t *conf)
{
	conf->names = hattrie_create();
}

static void conf_parse_end(conf_t *conf)
{
	if (conf->names) {
		hattrie_free(conf->names);
		conf->names = NULL;
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
	node_t *n = NULL;
	conf->_touched = CONF_ALL;
	WALK_LIST (n, conf->hooks) {
		conf_hook_t *hook = (conf_hook_t*)n;
		if ((hook->sections & conf->_touched) && hook->update) {
			hook->update(conf, hook->data);
		}
	}
}

/*!
 * \brief Make relative path absolute to given directory.
 *
 * If basedir is not provided, only normalization is performed.
 * If file is not provided, returns NULL.
 *
 * \param basedir Base directory.
 * \param file Relative file name.
 */
static char* conf_abs_path(const char *basedir, char *file)
{
	if (!file) {
		return NULL;
	}

	/* Make path absolute to the directory. */
	if (basedir && file[0] != '/') {
		char *basepath = strcdup(basedir, "/");
		char *path = strcdup(basepath, file);
		free(basepath);
		free(file);
		file = path;
	}

	/* Normalize. */
	return strcpath(file);
}

/*!
 * \brief Check if given path is an existing directory.
 *
 * \param path  Path to be checked.
 *
 * \return Given path is a directory.
 */
static bool is_existing_dir(const char *path)
{
	assert(path);

	struct stat st;

	if (stat(path, &st) == -1) {
		return false;
	}

	return S_ISDIR(st.st_mode);
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
	// Create PID file
	if (conf->rundir == NULL) {
		conf->rundir = strdup(RUN_DIR);
		if (conf->rundir == NULL) {
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

	/* Default interface. */
	conf_iface_t *ctl_if = conf->ctl.iface;
	if (!conf->ctl.have && ctl_if == NULL) {
		ctl_if = malloc(sizeof(conf_iface_t));
		memset(ctl_if, 0, sizeof(conf_iface_t));
		ctl_if->family = AF_UNIX;
		ctl_if->address = strdup("knot.sock");
		conf->ctl.iface = ctl_if;
	}

	/* Control interface. */
	if (ctl_if) {
		if (ctl_if->family == AF_UNIX) {
			ctl_if->address = conf_abs_path(conf->rundir,
			                                ctl_if->address);
			/* Check for ACL existence. */
			if (!EMPTY_LIST(conf->ctl.allow)) {
				log_server_warning("Control 'allow' statement "
				                   "does not affect UNIX sockets.\n");
			}
		} else if (ctl_if->port <= 0) {
			ctl_if->port = REMOTE_DPORT;
		}
	}

	/* Default RRL limits. */
	if (conf->rrl_slip < 0) {
		conf->rrl_slip = CONFIG_RRL_SLIP;
	}
	if (conf->rrl_size == 0) {
		conf->rrl_size = CONFIG_RRL_SIZE;
	}

	/* Default parallel transfers. */
	if (conf->xfers <= 0)
		conf->xfers = CONFIG_XFERS;


	/* Zones global configuration. */
	if (conf->storage == NULL) {
		conf->storage = strdup(STORAGE_DIR);
	}
	conf->storage = strcpath(conf->storage);
	if (conf->dnssec_keydir) {
		conf->dnssec_keydir = conf_abs_path(conf->storage,
		                                    conf->dnssec_keydir);
	}

	// Postprocess zones
	int ret = KNOT_EOK;
	node_t *n = NULL;
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
		if (zone->ixfr_fslimit == 0) { /* ixfr_fslimit is unsigned type */
			zone->ixfr_fslimit = conf->ixfr_fslimit;
		}

		// Default policy for DNSSEC signature lifetime
		if (zone->sig_lifetime <= 0) {
			zone->sig_lifetime = conf->sig_lifetime;
		}

		if (zone->serial_policy == 0) {
			zone->serial_policy = conf->serial_policy;
		}

		// Default zone file
		if (zone->file == NULL) {
			zone->file = strcdup(zone->name, "zone");
			if (!zone->file) {
				ret = KNOT_ENOMEM;
				continue;
			}
		}

		// Default data directories
		if (!zone->storage && conf->storage) {
			zone->storage = strdup(conf->storage);
		}
		if (!zone->dnssec_keydir && conf->dnssec_keydir) {
			zone->dnssec_keydir = strdup(conf->dnssec_keydir);
		}

		// Default policy for DNSSEC
		if (!zone->dnssec_keydir) {
			zone->dnssec_enable = 0;
		} else if (zone->dnssec_enable < 0) {
			zone->dnssec_enable = conf->dnssec_enable;
		}

		assert(zone->dnssec_enable == 0 || zone->dnssec_enable == 1);

		// DNSSEC required settings
		if (zone->dnssec_enable) {
			// Enable zone diffs (silently)
			zone->build_diffs = true;

			// Disable incoming XFRs
			if (!EMPTY_LIST(zone->acl.notify_in) ||
			    !EMPTY_LIST(zone->acl.xfr_in)
			) {
				log_server_warning("Automatic DNSSEC signing "
				                   "for zone '%s', disabling "
				                   "incoming XFRs.\n",
				                   zone->name);

				WALK_LIST_FREE(zone->acl.notify_in);
				WALK_LIST_FREE(zone->acl.xfr_in);
			}
		}

		// Resolve relative paths everywhere
		zone->storage = conf_abs_path(conf->storage, zone->storage);
		zone->file = conf_abs_path(zone->storage, zone->file);
		if (zone->dnssec_enable) {
			zone->dnssec_keydir = conf_abs_path(zone->storage,
			                                    zone->dnssec_keydir);
		}

		if (zone->storage == NULL ||
		    zone->file == NULL ||
		    (zone->dnssec_enable && zone->dnssec_keydir == NULL)
		) {
			free(zone->storage);
			free(zone->file);
			free(zone->dnssec_keydir);
			ret = KNOT_ENOMEM;
			continue;
		}

		/* Check paths existence. */
		if (!is_existing_dir(zone->storage)) {
			log_server_error("Storage dir '%s' does not exist.\n",
			                 zone->storage);
			ret = KNOT_EINVAL;
			continue;
		}
		if (zone->dnssec_enable && !is_existing_dir(zone->dnssec_keydir)) {
			log_server_error("DNSSEC key dir '%s' does not exist.\n",
			                 zone->dnssec_keydir);
			ret = KNOT_EINVAL;
			continue;

		}

		/* Create journal filename. */
		size_t zname_len = strlen(zone->name);
		size_t stor_len = strlen(zone->storage);
		size_t size = stor_len + zname_len + 9; // /diff.db,\0
		char *dest = malloc(size);
		if (dest == NULL) {
			ERR_ALLOC_FAILED;
			zone->ixfr_db = NULL; /* Not enough memory. */
			ret = KNOT_ENOMEM; /* Error report. */
			continue;
		}
		char *dpos = dest;
		memcpy(dpos, zone->storage, stor_len + 1);
		dpos += stor_len;
		if (zone->storage[stor_len - 1] != '/') {
			*(dpos++) = '/';
			*dpos = '\0';
		}

		const char *dbext = "diff.db";
		memcpy(dpos, zone->name, zname_len + 1);
		for (size_t i = 0; i < zname_len; ++i) {
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
		acl_insert(conf->ctl.acl, &addr, i);
	}

	return ret;
}

/*
 * Singletion configuration API.
 */

conf_t *s_config = NULL; /*! \brief Singleton config instance. */

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
	iface->name = strdup("localhost");
	iface->address = strdup("127.0.0.1");
	iface->port = CONFIG_DEFAULT_PORT;
	add_tail(&s_config->ifaces, &iface->n);
	++s_config->ifaces_count;

	/* Create default storage. */
	s_config->storage = strdup(STORAGE_DIR);

	/* Create default logs. */

	/* Syslog */
	conf_log_t *log = malloc(sizeof(conf_log_t));
	log->type = LOGT_SYSLOG;
	log->file = NULL;
	init_list(&log->map);

	conf_log_map_t *map = malloc(sizeof(conf_log_map_t));
	map->source = LOG_ANY;
	map->prios = LOG_MASK(LOG_WARNING)|LOG_MASK(LOG_ERR);
	add_tail(&log->map, &map->n);
	add_tail(&s_config->logs, &log->n);
	s_config->logs_count = 1;

	/* Stderr */
	log = malloc(sizeof(conf_log_t));
	log->type = LOGT_STDERR;
	log->file = NULL;
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
		s_config = NULL;
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
	if (f == NULL) {
		pthread_mutex_unlock(&_parser_lock);
		return KNOT_ENOENT;
	}

	// Parse config
	_parser_res = KNOT_EOK;
	new_config->filename = conf->filename;
	void *sc = NULL;
	conf_extra_t *extra = conf_extra_init(conf->filename);
	cf_lex_init_extra(extra, &sc);
	cf_set_in(f, sc);
	cf_parse(sc);
	cf_lex_destroy(sc);
	conf_extra_free(extra);
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
	conf_extra_t *extra = conf_extra_init("");
	cf_lex_init_extra(extra, &sc);
	switch_input(src, sc);
	cf_parse(sc);
	cf_lex_destroy(sc);
	conf_extra_free(extra);
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
	init_list(&c->groups);
	init_list(&c->keys);
	init_list(&c->ctl.allow);

	/* Defaults. */
	c->zone_checks = 0;
	c->notify_retries = CONFIG_NOTIFY_RETRIES;
	c->notify_timeout = CONFIG_NOTIFY_TIMEOUT;
	c->dbsync_timeout = CONFIG_DBSYNC_TIMEOUT;
	c->max_udp_payload = EDNS_MAX_UDP_PAYLOAD;
	c->sig_lifetime = KNOT_DNSSEC_DEFAULT_LIFETIME;
	c->serial_policy = CONFIG_SERIAL_DEFAULT;
	c->uid = -1;
	c->gid = -1;
	c->xfers = -1;
	c->rrl_slip = -1;
	c->build_diffs = 0; /* Disable by default. */
	c->logs_count = -1;

	/* DNSSEC. */
	c->dnssec_enable = 0;

	/* ACLs. */
	c->ctl.acl = acl_new();
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

	node_t *n = NULL, *nxt = NULL;

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
	conf->logs_count = -1;
	init_list(&conf->logs);

	// Free remote interfaces
	WALK_LIST_DELSAFE(n, nxt, conf->remotes) {
		conf_free_iface((conf_iface_t*)n);
	}
	conf->remotes_count = 0;
	init_list(&conf->remotes);

	// Free groups of remotes
	WALK_LIST_DELSAFE(n, nxt, conf->groups) {
		conf_free_group((conf_group_t *)n);
	}
	init_list(&conf->groups);

	// Free zones
	WALK_LIST_DELSAFE(n, nxt, conf->zones) {
		conf_free_zone((conf_zone_t*)n);
	}
	conf->zones_count = 0;
	init_list(&conf->zones);

	conf->dnssec_enable = -1;
	if (conf->filename) {
		free(conf->filename);
		conf->filename = NULL;
	}
	if (conf->identity) {
		free(conf->identity);
		conf->identity = NULL;
	}
	if (conf->version) {
		free(conf->version);
		conf->version = NULL;
	}
	if (conf->storage) {
		free(conf->storage);
		conf->storage = NULL;
	}
	if (conf->rundir) {
		free(conf->rundir);
		conf->rundir = NULL;
	}
	if (conf->pidfile) {
		free(conf->pidfile);
		conf->pidfile = NULL;
	}
	if (conf->nsid) {
		free(conf->nsid);
		conf->nsid = NULL;
	}
	if (conf->dnssec_keydir) {
		free(conf->dnssec_keydir);
		conf->dnssec_keydir = NULL;
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
	char *path = NULL;
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
			path = NULL;
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

	/* Synchronize. */
	synchronize_rcu();

	if (oldconf) {

		/* Copy hooks. */
		node_t *n = NULL;
		WALK_LIST (n, oldconf->hooks) {
			conf_hook_t *hook = (conf_hook_t*)n;
			conf_add_hook(nconf, hook->sections,
			              hook->update, hook->data);
		}

		/* Update hooks. */
		conf_update_hooks(nconf);

		/* Free old config. */
		conf_free(oldconf);
	}



	return KNOT_EOK;
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
	free(zone->ixfr_db);
	free(zone->dnssec_keydir);
	free(zone->storage);
	free(zone);
}

void conf_free_key(conf_key_t *k)
{
	knot_tsig_key_free(&k->k);
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

void conf_free_group(conf_group_t *group)
{
	conf_group_remote_t *remote, *next;
	WALK_LIST_DELSAFE(remote, next, group->remotes) {
		free(remote->name);
		free(remote);
	}

	free(group);
}

void conf_free_log(conf_log_t *log)
{
	if (!log) {
		return;
	}

	free(log->file);

	/* Free loglevel mapping. */
	node_t *n = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(n, nxt, log->map) {
		free((conf_log_map_t*)n);
	}

	free(log);
}
