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
#include "common-knot/strlcat.h"
#include "common-knot/strlcpy.h"
#include "common/mem.h"
#include "knot/conf/conf.h"
#include "knot/conf/extra.h"
#include "knot/knot.h"
#include "knot/ctl/remote.h"
#include "knot/nameserver/internet.h"

/*
 * Defaults.
 */

#define DEFAULT_CONFIG CONFIG_DIR "/" "knot.conf" /*!< \brief Default config path. */
#define ERROR_BUFFER_SIZE       512 /*!< \brief Error buffer size. */

/*
 * Utilities.
 */

/* Prototypes for cf-parse.y */
extern int cf_parse(void *scanner);
extern int cf_get_lineno(void *scanner);
extern char *cf_get_text(void *scanner);
extern conf_extra_t *cf_get_extra(void *scanner);
extern int cf_lex_init_extra(void *, void *scanner);
extern void cf_set_in(FILE *f, void *scanner);
extern void cf_lex_destroy(void *scanner);
extern void switch_input(const char *str, void *scanner);

conf_t *new_config = NULL; /*!< \brief Currently parsed config. */
static volatile int _parser_res = 0; /*!< \brief Parser result. */
static pthread_mutex_t _parser_lock = PTHREAD_MUTEX_INITIALIZER;

static void cf_print_error(void *scanner, int priority, const char *msg)
{
	conf_extra_t *extra = NULL;
	int lineno = -1;
	char *text = "?";
	const char *filename = NULL;
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

	log_msg(priority, "config, file '%s', line %d, token '%s', %s",
	        filename, lineno, text, msg);
}

/*! \brief Config error report. */
void cf_error(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, LOG_ERR, buffer);
	_parser_res = KNOT_EPARSEFAIL;
}

/*! \brief Config warning report. */
void cf_warning(void *scanner, const char *format, ...)
{
	char buffer[ERROR_BUFFER_SIZE];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	cf_print_error(scanner, LOG_WARNING, buffer);
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
	if (conf->max_tcp_clients < 1) {
		conf->max_tcp_clients = CONFIG_MAXTCP;
	}

	/* Default interface. */
	conf_iface_t *ctl_if = conf->ctl.iface;
	if (!conf->ctl.have && ctl_if == NULL) {
		ctl_if = malloc(sizeof(conf_iface_t));
		memset(ctl_if, 0, sizeof(conf_iface_t));
		sockaddr_set(&ctl_if->addr, AF_UNIX, "knot.sock", 0);
		conf->ctl.iface = ctl_if;
	}

	/* Control interface. */
	if (ctl_if) {
		if (ctl_if->addr.ss_family == AF_UNIX) {
			char *full_path = malloc(SOCKADDR_STRLEN);
			memset(full_path, 0, SOCKADDR_STRLEN);
			sockaddr_tostr(&ctl_if->addr, full_path, SOCKADDR_STRLEN);

			/* Convert to absolute path. */
			full_path = conf_abs_path(conf->rundir, full_path);
			if(full_path) {
				sockaddr_set(&ctl_if->addr, AF_UNIX, full_path, 0);
				free(full_path);
			}

			/* Check for ACL existence. */
			if (!EMPTY_LIST(conf->ctl.allow)) {
				log_warning("control 'allow' statement does not "
				            "affect UNIX sockets");
			}
		} else if (sockaddr_port(&ctl_if->addr) <= 0) {
			sockaddr_port_set(&ctl_if->addr, REMOTE_DPORT);
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

	if (conf->timer_db == NULL) {
		conf->timer_db = strdup("timers");
	}
	conf->timer_db = conf_abs_path(conf->storage, conf->timer_db);

	if (conf->dnssec_keydir) {
		conf->dnssec_keydir = conf_abs_path(conf->storage,
		                                    conf->dnssec_keydir);
	}

	// Postprocess zones
	int ret = KNOT_EOK;

	/* Initialize query plan if modules exist. */
	if (!EMPTY_LIST(conf->query_modules)) {
		conf->query_plan = query_plan_create(NULL);
		if (conf->query_plan == NULL) {
			return KNOT_ENOMEM;
		}
	}

	/* Load query modules. */
	struct query_module *module = NULL;
	WALK_LIST(module, conf->query_modules) {
		ret = module->load(conf->query_plan, module);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	const bool sorted = false;
	hattrie_iter_t *z_iter = hattrie_iter_begin(conf->zones, sorted);
	if (z_iter == NULL) {
		return KNOT_ERROR;
	}
	for (; !hattrie_iter_finished(z_iter) && ret == KNOT_EOK; hattrie_iter_next(z_iter)) {

		conf_zone_t *zone = (conf_zone_t *)*hattrie_iter_val(z_iter);

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

		// Default policy for maximum ZONE size
		if (zone->max_zone_size == 0) {
			zone->max_zone_size = conf->max_zone_size;
		}

		// Default policy for DNSSEC signature lifetime
		if (zone->sig_lifetime <= 0) {
			zone->sig_lifetime = conf->sig_lifetime;
		}

		// Default request EDNS option.
		if (zone->req_edns_data == NULL) {
			zone->req_edns_code = conf->req_edns_code;
			zone->req_edns_data = conf->req_edns_data;
			zone->req_edns_data_len = conf->req_edns_data_len;
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
				log_zone_str_notice(zone->name, "automatic "
					"DNSSEC signing enabled, disabling "
					"incoming XFRs");

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
			log_error("storage directory '%s' does not exist",
			          zone->storage);
			ret = KNOT_EINVAL;
			continue;
		}
		if (zone->dnssec_enable && !is_existing_dir(zone->dnssec_keydir)) {
			log_error("DNSSEC key directory '%s' does not exist",
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

		/* Initialize query plan if modules exist. */
		if (!EMPTY_LIST(zone->query_modules)) {
			zone->query_plan = query_plan_create(NULL);
			if (zone->query_plan == NULL) {
				ret = KNOT_ENOMEM;
				continue;
			}

			/* Only supported zone class is now IN. */
			internet_query_plan(zone->query_plan);
		}

		/* Load query modules. */
		struct query_module *module = NULL;
		WALK_LIST(module, zone->query_modules) {
			ret = module->load(zone->query_plan, module);
			if (ret != KNOT_EOK) {
				break;
			}
		}
	}
	hattrie_iter_free(z_iter);

	/* Update UID and GID. */
	if (conf->uid < 0) conf->uid = getuid();
	if (conf->gid < 0) conf->gid = getgid();

	return ret;
}

/*
 * Singletion configuration API.
 */

conf_t *s_config = NULL; /*! \brief Singleton config instance. */

/*!
 * \brief Parse config (from file).
 * \return yyparser return value.
 */
static int conf_fparser(conf_t *conf)
{
	if (!conf->filename) {
		return KNOT_EINVAL;
	}

	/* Find real path of the config file */
	char *config_realpath = realpath(conf->filename, NULL);
	if (config_realpath == NULL) {
		return knot_map_errno(EINVAL, ENOENT);
	}

	/* Check if accessible. */
	if (access(config_realpath, F_OK | R_OK) != 0) {
		free(config_realpath);
		return KNOT_EACCES;
	}

	int ret = KNOT_EOK;
	pthread_mutex_lock(&_parser_lock);

	// {
	// Hook new configuration
	new_config = conf;
	FILE *f = fopen(config_realpath, "r");
	if (f == NULL) {
		free(config_realpath);
		pthread_mutex_unlock(&_parser_lock);
		return KNOT_ENOENT;
	}

	// Parse config
	_parser_res = KNOT_EOK;
	new_config->filename = conf->filename;
	void *sc = NULL;
	conf_extra_t *extra = conf_extra_init(config_realpath);
	cf_lex_init_extra(extra, &sc);
	cf_set_in(f, sc);
	cf_parse(sc);
	cf_lex_destroy(sc);
	conf_extra_free(extra);
	free(config_realpath);
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
	const char *oldfn = new_config->filename;
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

conf_t *conf_new(const char *path)
{
	conf_t *c = malloc(sizeof(conf_t));
	memset(c, 0, sizeof(conf_t));

	/* Add path. */
	c->filename = path;

	/* Initialize lists. */
	init_list(&c->logs);
	init_list(&c->ifaces);
	init_list(&c->hooks);
	init_list(&c->remotes);
	init_list(&c->groups);
	init_list(&c->keys);
	init_list(&c->ctl.allow);

	/* Zones container. */
	c->zones = hattrie_create();
	init_list(&c->query_modules);

	/* Defaults. */
	c->zone_checks = 0;
	c->notify_retries = CONFIG_NOTIFY_RETRIES;
	c->notify_timeout = CONFIG_NOTIFY_TIMEOUT;
	c->dbsync_timeout = CONFIG_DBSYNC_TIMEOUT;
	c->max_udp_payload = KNOT_EDNS_MAX_UDP_PAYLOAD;
	c->sig_lifetime = KNOT_DNSSEC_DEFAULT_LIFETIME;
	c->serial_policy = CONFIG_SERIAL_DEFAULT;
	c->uid = -1;
	c->gid = -1;
	c->xfers = -1;
	c->rrl_slip = -1;
	c->build_diffs = 0; /* Disable by default. */
	c->max_zone_size = (~((size_t)0)); /* Unlimited by default. */

	/* DNSSEC. */
	c->dnssec_enable = 0;

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

	node_t *n = NULL, *nxt = NULL;

	// Unload hooks
	if (unload_hooks) {
		WALK_LIST_DELSAFE(n, nxt, conf->hooks) {
			/*! \todo Call hook unload (issue #1583) */
			free((conf_hook_t*)n);
		}
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
	init_list(&conf->ifaces);

	// Free logs
	WALK_LIST_DELSAFE(n, nxt, conf->logs) {
		conf_free_log((conf_log_t*)n);
	}
	init_list(&conf->logs);

	// Free remote interfaces
	WALK_LIST_DELSAFE(n, nxt, conf->remotes) {
		conf_free_iface((conf_iface_t*)n);
	}
	init_list(&conf->remotes);

	// Free groups of remotes
	WALK_LIST_DELSAFE(n, nxt, conf->groups) {
		conf_free_group((conf_group_t *)n);
	}
	init_list(&conf->groups);

	// Free zones
	if (conf->zones) {
		hattrie_free(conf->zones);
		conf->zones = NULL;
	}

	/* Unload query modules. */
	struct query_module *module = NULL, *next = NULL;
	WALK_LIST_DELSAFE(module, next, conf->query_modules) {
		query_module_close(module);
	}

	/* Free query plan. */
	query_plan_free(conf->query_plan);

	conf->dnssec_enable = -1;
	if (conf->filename) {
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
	if (conf->timer_db) {
		free(conf->timer_db);
		conf->timer_db = NULL;
	}

	/* Free remote control list. */
	WALK_LIST_DELSAFE(n, nxt, conf->ctl.allow) {
		conf_free_remote((conf_remote_t*)n);
	}
	init_list(&conf->remotes);

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

	/* Free config. */
	free(conf);
}

const char* conf_find_default()
{
	return DEFAULT_CONFIG;
}

int conf_open(const char* path)
{
	/* Create new config. */
	conf_t *nconf = conf_new(path);
	if (nconf == NULL) {
		return KNOT_ENOMEM;
	}

	/* Parse config. */
	int ret = conf_fparser(nconf);
	if (ret == KNOT_EOK) {
		/* Postprocess config. */
		ret = conf_process(nconf);
	}

	if (ret != KNOT_EOK) {
		conf_free(nconf);
		return ret;
	}

	/* Replace current config. */
	conf_t **current_config = &s_config;
	conf_t *oldconf = rcu_xchg_pointer(current_config, nconf);

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
			log_warning("cannot expand non-login user home "
			            "directory '%s', use full path instead",
				    path);
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
		size_t npath_size = plen + tild_len + 1;
		char *npath = malloc(npath_size);
		if (npath == NULL) {
			free(tild_exp);
			return NULL;
		}
		npath[0] = '\0';
		strlcpy(npath, path, npath_size);
		strlcat(npath, tild_exp, npath_size);

		// Append remainder
		++remainder;
		strlcat(npath, remainder, npath_size);

		free(tild_exp);
		free(path);
		path = npath;
	}

	return path;
}

size_t conf_udp_threads(const conf_t *conf)
{
	if (conf->workers < 1) {
		return dt_optimal_size();
	}

	return conf->workers;
}

size_t conf_tcp_threads(const conf_t *conf)
{
	size_t thrcount = conf_udp_threads(conf);
	return MAX(thrcount * 2, CONFIG_XFERS);
}

int conf_bg_threads(const conf_t *conf)
{
	if (conf->bg_workers < 1) {
		return MIN(dt_optimal_size(), CONFIG_XFERS);
	}

	return conf->bg_workers;
}


void conf_init_zone(conf_zone_t *zone)
{
	if (!zone) {
		return;
	}

	memset(zone, 0, sizeof(conf_zone_t));

	// Default policy applies.
	zone->enable_checks = -1;
	zone->notify_timeout = -1;
	zone->notify_retries = 0;
	zone->dbsync_timeout = -1;
	zone->disable_any = -1;
	zone->build_diffs = -1;
	zone->sig_lifetime = -1;
	zone->dnssec_enable = -1;

	// Initialize ACL lists.
	init_list(&zone->acl.xfr_in);
	init_list(&zone->acl.xfr_out);
	init_list(&zone->acl.notify_in);
	init_list(&zone->acl.notify_out);
	init_list(&zone->acl.update_in);

	// Initialize synthesis templates
	init_list(&zone->query_modules);
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

	/* Unload query modules. */
	struct query_module *module = NULL, *next = NULL;
	WALK_LIST_DELSAFE(module, next, zone->query_modules) {
		query_module_close(module);
	}

	/* Free query plan. */
	query_plan_free(zone->query_plan);

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

	free(group->name);
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
