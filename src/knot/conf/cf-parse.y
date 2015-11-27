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
/*!
 * \file cf-parse.y
 *
 * \author Ondrej Sury <ondrej.sury@nic.cz>
 *
 * \brief Server configuration structures and API.
 */
%{

#include <config.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include "common-knot/sockaddr.h"
#include "common-knot/strlcat.h"
#include "common-knot/strlcpy.h"
#include "libknot/dname.h"
#include "libknot/binary.h"
#include "libknot/rrtype/opt.h"
#include "knot/server/rrl.h"
#include "knot/nameserver/query_module.h"
#include "knot/conf/conf.h"
#include "knot/conf/libknotd_la-cf-parse.h" /* Automake generated header. */

extern int cf_lex (YYSTYPE *lvalp, void *scanner);
extern void cf_error(void *scanner, const char *format, ...);
extern void cf_warning(void *scanner, const char *format, ...);
extern conf_t *new_config;
static conf_iface_t *this_iface = 0;
static conf_iface_t *this_remote = 0;
static conf_zone_t *this_zone = 0;
static conf_group_t *this_group = 0;
static list_t *this_list = 0;
static conf_log_t *this_log = 0;
static conf_log_map_t *this_logmap = 0;
//#define YYERROR_VERBOSE 1

static char *cache_hostname = NULL;

#define SET_NUM(out, in, min, max, name)				\
{									\
	if (in < min || in > max) {					\
		cf_error(scanner, "'%s' is out of range (%u-%u)",	\
		         name, min, max);				\
	} else {							\
		out = in;						\
	}								\
}

#define SET_UINT16(out, in, name) SET_NUM(out, in, 0, UINT16_MAX, name);
#define SET_INT(out, in, name) SET_NUM(out, in, 0, INT_MAX, name);
#define SET_SIZE(out, in, name) SET_NUM(out, in, 0, SIZE_MAX, name);

static void conf_start(void *scanner)
{
	cache_hostname = NULL;
}

static void conf_init_iface(void *scanner, char* ifname)
{
	this_iface = malloc(sizeof(conf_iface_t));
	if (this_iface == NULL) {
		cf_error(scanner, "not enough memory when allocating interface");
		return;
	}
	memset(this_iface, 0, sizeof(conf_iface_t));
	this_iface->name = ifname;
}

static void conf_set_iface(void *scanner, struct sockaddr_storage *ss, int family, char* addr, int port)
{
	int ret = sockaddr_set(ss, family, addr, port);
	if (ret != KNOT_EOK) {
		cf_error(scanner, "invalid address for '%s': %s@%d\n",
		                  this_iface->name, addr, port);
	}
	free(addr);
}

static void conf_start_iface(void *scanner, char* ifname)
{
	conf_init_iface(scanner, ifname);
	add_tail(&new_config->ifaces, &this_iface->n);
}

static conf_iface_t *conf_get_remote(const char *name)
{
	conf_iface_t *remote;
	WALK_LIST (remote, new_config->remotes) {
		if (strcmp(remote->name, name) == 0) {
			return remote;
		}
	}

	return NULL;
}

static void conf_start_remote(void *scanner, char *remote)
{
	if (conf_get_remote(remote) != NULL) {
		cf_error(scanner, "remote '%s' already defined", remote);
		return;
	}

	this_remote = malloc(sizeof(conf_iface_t));
	if (this_remote == NULL) {
		cf_error(scanner, "not enough memory when allocating remote");
		return;
	}

	memset(this_remote, 0, sizeof(conf_iface_t));
	this_remote->name = remote;
	add_tail(&new_config->remotes, &this_remote->n);
}

static void conf_remote_set_via(void *scanner, char *item) {
	/* Find existing node in interfaces. */
	node_t* r = 0; conf_iface_t* found = 0;
	WALK_LIST (r, new_config->ifaces) {
		if (strcmp(((conf_iface_t*)r)->name, item) == 0) {
			found = (conf_iface_t*)r;
			break;
		}
	}

	/* Check */
	if (!found) {
		cf_error(scanner, "interface '%s' is not defined", item);
	} else {
		memcpy(&this_remote->via, &found->addr, sizeof(struct sockaddr_storage));
		sockaddr_port_set(&this_remote->via, 0);
	}
}

static conf_group_t *conf_get_group(const char *name)
{
	conf_group_t *group;
	WALK_LIST (group, new_config->groups) {
		if (strcmp(group->name, name) == 0) {
			return group;
		}
	}

	return NULL;
}

static void conf_start_group(void *scanner, char *name)
{
	conf_group_t *group = conf_get_group(name);
	if (group) {
		cf_error(scanner, "group '%s' already defined", name);
		return;
	}

	if (conf_get_remote(name) != NULL) {
		cf_error(scanner, "group name '%s' conflicts with remote name",
		         name);
		free(name);
		return;
	}

	/* Add new group. */

	group = calloc(1, sizeof(conf_group_t));
	if (!group) {
		cf_error(scanner, "out of memory");
		free(name);
		return;
	}

	group->name = name;
	init_list(&group->remotes);

	add_tail(&new_config->groups, &group->n);
	this_group = group;
}

static void conf_add_member_into_group(void *scanner, char *name)
{
	if (!this_group) {
		cf_error(scanner, "parser error, variable 'this_group' null");
		free(name);
		return;
	}

	if (conf_get_remote(name) == NULL) {
		cf_error(scanner, "remote '%s' is not defined", name);
		free(name);
		return;
	}

	// add the remote into the group while silently ignoring duplicates

	conf_group_remote_t *remote;
	node_t *n;
	WALK_LIST (n, this_group->remotes) {
		remote = (conf_group_remote_t *)n;
		if (strcmp(remote->name, name) == 0) {
			free(name);
			return;
		}
	}

	remote = calloc(1, sizeof(conf_group_remote_t));
	remote->name = name;
	add_tail(&this_group->remotes, &remote->n);
}

static bool set_remote_or_group(void *scanner, char *name,
				void (*install)(void *, conf_iface_t *))
{
	// search remotes

	conf_iface_t *remote = conf_get_remote(name);
	if (remote) {
		install(scanner, remote);
		return true;
	}

	// search groups

	conf_group_t *group = conf_get_group(name);
	if (group) {
		conf_group_remote_t *group_remote;
		WALK_LIST (group_remote, group->remotes) {
			remote = conf_get_remote(group_remote->name);
			if (!remote)
				continue;
			install(scanner, remote);
		}

		return true;
	}

	return false;
}

static void conf_acl_item_install(void *scanner, conf_iface_t *found)
{

	// additional check for transfers

	if ((this_list == &this_zone->acl.xfr_in || this_list == &this_zone->acl.notify_out)
	    && sockaddr_port(&found->addr) == 0)
	{
		cf_error(scanner, "remote specified for XFR/IN or "
		"NOTIFY/OUT needs to have valid port!");
		return;
	}

	// silently skip duplicates

	conf_remote_t *remote;
	WALK_LIST (remote, *this_list) {
		if (remote->remote == found) {
			return;
		}
	}

	// add into the list

	remote = malloc(sizeof(conf_remote_t));
	if (!remote) {
		cf_error(scanner, "out of memory");
		return;
	}

	remote->remote = found;
	add_tail(this_list, &remote->n);
}

static void conf_acl_item(void *scanner, char *item)
{
	if (!set_remote_or_group(scanner, item, conf_acl_item_install)) {
		cf_error(scanner, "remote or group '%s' not defined", item);
	}

	free(item);
}

static void query_module_create(void *scanner, const char *name, const char *param, bool on_zone)
{
	struct query_module *module = query_module_open(new_config, name, param, NULL);
	if (module == NULL) {
		cf_error(scanner, "cannot load query module '%s'", name);
		return;
	}

	if (on_zone) {
		add_tail(&this_zone->query_modules, &module->node);
	} else {
		add_tail(&new_config->query_modules, &module->node);
	}
}

static int conf_key_exists(void *scanner, char *item)
{
	/* Find existing node in keys. */
	knot_dname_t *sample = knot_dname_from_str_alloc(item);
	knot_dname_to_lower(sample);
	conf_key_t* r = 0;
	WALK_LIST (r, new_config->keys) {
		if (knot_dname_cmp(r->k.name, sample) == 0) {
			cf_error(scanner, "key '%s' is already defined", item);
			knot_dname_free(&sample, NULL);
			return 1;
		}
	}

	knot_dname_free(&sample, NULL);
	return 0;
}

static int conf_key_add(void *scanner, knot_tsig_key_t **key, char *item)
{
	/* Reset */
	*key = 0;

	/* Find in keys */
	knot_dname_t *sample = knot_dname_from_str_alloc(item);
	knot_dname_to_lower(sample);

	conf_key_t* r = 0;
	WALK_LIST (r, new_config->keys) {
		if (knot_dname_cmp(r->k.name, sample) == 0) {
			*key = &r->k;
			knot_dname_free(&sample, NULL);
			return 0;
		}
	}

	cf_error(scanner, "key '%s' is not defined", item);
	knot_dname_free(&sample, NULL);
	return 1;
}

static void conf_zone_start(void *scanner, char *name) {
	this_zone = malloc(sizeof(conf_zone_t));
	if (this_zone == NULL || name == NULL) {
		cf_error(scanner, "out of memory while allocating zone config");
		return;
	}

	conf_init_zone(this_zone);

	// Append mising dot to ensure FQDN
	size_t nlen = strlen(name);
	if (name[nlen - 1] != '.') {
		this_zone->name = malloc(nlen + 2);
		if (this_zone->name != NULL) {
			memcpy(this_zone->name, name, nlen);
			this_zone->name[nlen] = '.';
			this_zone->name[++nlen] = '\0';
		}
		free(name);
	} else {
		this_zone->name = name; /* Already FQDN */
	}

	// Convert zone name to lower-case.
	for (size_t i = 0; this_zone->name[i]; i++) {
		this_zone->name[i] = tolower((unsigned char)this_zone->name[i]);
	}

	/* Check domain name. */
	knot_dname_t *dn = NULL;
	if (this_zone->name != NULL) {
		dn = knot_dname_from_str_alloc(this_zone->name);
	}
	if (dn == NULL) {
		free(this_zone->name);
		free(this_zone);
		this_zone = NULL;
		cf_error(scanner, "invalid zone origin");
	} else {
	/* Check for duplicates. */
	if (hattrie_tryget(new_config->zones, (const char *)dn,
	                   knot_dname_size(dn)) != NULL) {
		cf_error(scanner, "zone '%s' is already present, refusing to "
		         "duplicate", this_zone->name);
		knot_dname_free(&dn, NULL);
		free(this_zone->name);
		this_zone->name = NULL;
		/* Must not free, some versions of flex might continue after
		 * error and segfault.
		 * free(this_zone); this_zone = NULL;
		 */
		return;
	}

	*hattrie_get(new_config->zones, (const char *)dn,
	             knot_dname_size(dn)) = this_zone;
	knot_dname_free(&dn, NULL);
	}
}

/*! \brief Replace string value. */
static void opt_replace(char **opt, char *new_opt, bool val)
{
	/* Clear old value. */
	free(*opt);
	*opt = NULL;
	/* Replace if val is True. */
	if (val) {
		*opt = new_opt;
	} else {
		free(new_opt);
	}
}

static char *get_hostname(void *scanner)
{
	if (cache_hostname) {
		return strdup(cache_hostname);
	}

	char *fqdn = sockaddr_hostname();
	if (!fqdn) {
		cf_warning(scanner, "cannot retrieve host FQDN");
		return NULL;
	}

	cache_hostname = fqdn;

	return fqdn;
}

/*! \brief Generate automatic defaults for server identity, version and NSID. */
static void ident_auto(void *scanner, int tok, conf_t *conf, bool val)
{
	switch(tok) {
	case SVERSION:
		opt_replace(&conf->version, strdup("Knot DNS " PACKAGE_VERSION), val);
		break;
	case IDENTITY:
		opt_replace(&conf->identity, get_hostname(scanner), val);
		break;
	case NSID:
		opt_replace(&conf->nsid, get_hostname(scanner), val);
		if (conf->nsid) {
			conf->nsid_len = strlen(conf->nsid);
		}
		break;
	default:
		break;
	}
}

%}

%pure-parser
%parse-param{void *scanner}
%lex-param{void *scanner}
%name-prefix = "cf_"

%union {
	struct {
		char *t;
		long i;
		size_t l;
		knot_tsig_algorithm_t alg;
	} tok;
}

%token END INVALID_TOKEN
%token <tok> TEXT
%token <tok> HEXSTR
%token <tok> NUM
%token <tok> INTERVAL
%token <tok> SIZE
%token <tok> BOOL

%token <tok> SYSTEM IDENTITY HOSTNAME SVERSION NSID KEY KEYS
%token <tok> MAX_UDP_PAYLOAD
%token <tok> REQ_EDNS_OPT
%token <tok> TSIG_ALGO_NAME
%token <tok> WORKERS
%token <tok> BACKGROUND_WORKERS
%token <tok> ASYNC_START
%token <tok> USER
%token <tok> RUNDIR
%token <tok> PIDFILE

%token <tok> REMOTES
%token <tok> GROUPS

%token <tok> ZONES FILENAME
%token <tok> DISABLE_ANY
%token <tok> SEMANTIC_CHECKS
%token <tok> NOTIFY_RETRIES
%token <tok> NOTIFY_TIMEOUT
%token <tok> DBSYNC_TIMEOUT
%token <tok> IXFR_FSLIMIT
%token <tok> XFR_IN
%token <tok> XFR_OUT
%token <tok> UPDATE_IN
%token <tok> NOTIFY_IN
%token <tok> NOTIFY_OUT
%token <tok> BUILD_DIFFS
%token <tok> MAX_CONN_IDLE
%token <tok> MAX_CONN_HS
%token <tok> MAX_CONN_REPLY
%token <tok> MAX_TCP_CLIENTS
%token <tok> RATE_LIMIT
%token <tok> RATE_LIMIT_SIZE
%token <tok> RATE_LIMIT_SLIP
%token <tok> TRANSFERS
%token <TOK> STORAGE
%token <TOK> TIMER_DB
%token <tok> DNSSEC_ENABLE
%token <tok> DNSSEC_KEYDIR
%token <tok> SIGNATURE_LIFETIME
%token <tok> SERIAL_POLICY
%token <tok> SERIAL_POLICY_VAL
%token <tok> QUERY_MODULE

%token <tok> INTERFACES ADDRESS PORT
%token <tok> IPA
%token <tok> IPA6
%token <tok> VIA

%token <tok> CONTROL ALLOW LISTEN_ON

%token <tok> LOG
%token <tok> LOG_DEST
%token <tok> LOG_SRC
%token <tok> LOG_LEVEL

%%

config: { conf_start(scanner); } conf_entries END { return 0; } ;

conf_entries:
 /* EMPTY */
 | conf_entries conf
 ;

interface_start:
 | TEXT { conf_start_iface(scanner, $1.t); }
 | REMOTES  { conf_start_iface(scanner, strdup($1.t)); } /* Allow strings reserved by token. */
 | LOG_SRC  { conf_start_iface(scanner, strdup($1.t)); }
 | LOG  { conf_start_iface(scanner, strdup($1.t)); }
 | LOG_LEVEL  { conf_start_iface(scanner, strdup($1.t)); }
 | CONTROL    { conf_start_iface(scanner, strdup($1.t)); }
 ;

interface:
 | interface PORT NUM ';' {
     if (this_iface->addr.ss_family == AF_UNSPEC) {
       cf_error(scanner, "can't set port number before interface address\n");
     } else {
       sockaddr_port_set(&this_iface->addr, $3.i);
     }
   }
 | interface ADDRESS IPA ';' {
     conf_set_iface(scanner, &this_iface->addr, AF_INET, $3.t, CONFIG_DEFAULT_PORT);
   }
 | interface ADDRESS IPA '@' NUM ';' {
     conf_set_iface(scanner, &this_iface->addr, AF_INET, $3.t, $5.i);
   }
 | interface ADDRESS IPA6 ';' {
     conf_set_iface(scanner, &this_iface->addr, AF_INET6, $3.t, CONFIG_DEFAULT_PORT);
   }
 | interface ADDRESS IPA6 '@' NUM ';' {
     conf_set_iface(scanner, &this_iface->addr, AF_INET6, $3.t, $5.i);
   }
 ;

interfaces:
   INTERFACES '{'
 | interfaces interface_start '{' interface '}' {
   if (this_iface->addr.ss_family == AF_UNSPEC) {
     cf_error(scanner, "interface '%s' has no defined address", this_iface->name);
   }
 }
 ;

system:
   SYSTEM '{'
 | system SVERSION TEXT ';' { new_config->version = $3.t; }
 | system SVERSION BOOL ';' { ident_auto(scanner, SVERSION, new_config, $3.i); }
 | system IDENTITY TEXT ';' { new_config->identity = $3.t; }
 | system IDENTITY BOOL ';' { ident_auto(scanner, IDENTITY, new_config, $3.i); }
 | system HOSTNAME TEXT ';' {
     cf_warning(scanner, "option 'system.hostname' is deprecated, "
                         "use 'system.identity' instead");
     free($3.t);
 }
 | system NSID HEXSTR ';' { new_config->nsid = $3.t; new_config->nsid_len = $3.l; }
 | system NSID TEXT ';' { new_config->nsid = $3.t; new_config->nsid_len = strlen(new_config->nsid); }
 | system NSID BOOL ';' { ident_auto(scanner, NSID, new_config, $3.i); }
 | system MAX_UDP_PAYLOAD NUM ';' {
     SET_NUM(new_config->max_udp_payload, $3.i, KNOT_EDNS_MIN_UDP_PAYLOAD,
             KNOT_EDNS_MAX_UDP_PAYLOAD, "max-udp-payload");
 }
 | system STORAGE TEXT ';' {
     cf_warning(scanner, "option 'system.storage' was relocated, "
                         "use 'zones.storage' instead");
     new_config->storage = $3.t;
 }
 | system RUNDIR TEXT ';' { new_config->rundir = $3.t; }
 | system PIDFILE TEXT ';' { new_config->pidfile = $3.t; }
 | system KEY TSIG_ALGO_NAME TEXT ';' {
     cf_warning(scanner, "option 'system.key' is deprecated and it has no effect");
     free($4.t);
 }
 | system WORKERS NUM ';' {
     SET_NUM(new_config->workers, $3.i, 1, 255, "workers");
 }
 | system BACKGROUND_WORKERS NUM ';' {
     SET_NUM(new_config->bg_workers, $3.i, 1, 255, "background-workers");
 }
 | system ASYNC_START BOOL ';' {
     new_config->async_start = $3.i;
 }
 | system USER TEXT ';' {
     new_config->uid = new_config->gid = -1; // Invalidate
     char* dpos = strchr($3.t, '.'); // Find uid.gid format
     if (dpos != NULL) {
        struct group *grp = getgrnam(dpos + 1); // Skip dot
        if (grp != NULL) {
          new_config->gid = grp->gr_gid;
        } else {
          cf_error(scanner, "invalid group name '%s'", dpos + 1);
        }
        *dpos = '\0'; // Cut off
     }
     struct passwd* pwd = getpwnam($3.t);
     if (pwd != NULL) {
       new_config->uid = pwd->pw_uid;
     } else {
       cf_error(scanner, "invalid user name '%s'", $3.t);
     }

     free($3.t);
 }
 | system MAX_CONN_IDLE INTERVAL ';' {
	SET_INT(new_config->max_conn_idle, $3.i, "max-conn-idle");
 }
 | system MAX_CONN_IDLE NUM ';' {
	SET_INT(new_config->max_conn_idle, $3.i, "max-conn-idle");
 }
 | system MAX_CONN_HS INTERVAL ';' {
	SET_INT(new_config->max_conn_hs, $3.i, "max-conn-handshake");
 }
 | system MAX_CONN_HS NUM ';' {
	SET_INT(new_config->max_conn_hs, $3.i, "max-conn-handshake");
 }
 | system MAX_CONN_REPLY INTERVAL ';' {
	SET_INT(new_config->max_conn_reply, $3.i, "max-conn-reply");
 }
 | system MAX_CONN_REPLY NUM ';' {
	SET_INT(new_config->max_conn_reply, $3.i, "max-conn-reply");
 }
 | system MAX_TCP_CLIENTS NUM ';' {
	SET_INT(new_config->max_tcp_clients, $3.i, "max-tcp-clients");
 }
 | system RATE_LIMIT NUM ';' {
	SET_INT(new_config->rrl, $3.i, "rate-limit");
 }
 | system RATE_LIMIT_SIZE SIZE ';' {
	SET_SIZE(new_config->rrl_size, $3.l, "rate-limit-size");
 }
 | system RATE_LIMIT_SIZE NUM ';' {
	SET_SIZE(new_config->rrl_size, $3.i, "rate-limit-size");
 }
 | system RATE_LIMIT_SLIP NUM ';' {
	SET_NUM(new_config->rrl_slip, $3.i, 1, RRL_SLIP_MAX, "rate-limit-slip");
 }
 | system TRANSFERS NUM ';' {
	SET_INT(new_config->xfers, $3.i, "transfers");
 }
 ;

keys:
   KEYS '{'
 | keys TEXT TSIG_ALGO_NAME TEXT ';' {
     /* Check algorithm length. */
     if (knot_tsig_digest_length($3.alg) == 0) {
        cf_error(scanner, "unsupported digest algorithm");
     }

     /* Normalize to FQDN */
     char *fqdn = $2.t;
     size_t fqdnl = strlen(fqdn);
     if (fqdn[fqdnl - 1] != '.') {
        fqdnl = ((fqdnl + 2)/4+1)*4; /* '.', '\0' */
        char* tmpdn = malloc(fqdnl);
	if (!tmpdn) {
	   cf_error(scanner, "out of memory when allocating string");
	   free(fqdn);
	   fqdn = NULL;
	} else {
	   strlcpy(tmpdn, fqdn, fqdnl);
	   strlcat(tmpdn, ".", fqdnl);
	   free(fqdn);
	   fqdn = tmpdn;
	}
     }

     if (fqdn != NULL && !conf_key_exists(scanner, fqdn)) {
         knot_dname_t *dname = knot_dname_from_str_alloc(fqdn);
	 if (!dname) {
             cf_error(scanner, "key name '%s' not in valid domain name format",
                      fqdn);
         } else {
             knot_dname_to_lower(dname);
             conf_key_t *k = malloc(sizeof(conf_key_t));
             memset(k, 0, sizeof(conf_key_t));
             k->k.name = dname;
             k->k.algorithm = $3.alg;
             if (knot_binary_from_base64($4.t, &(k->k.secret)) != 0) {
                 cf_error(scanner, "invalid key secret '%s'", $4.t);
                 knot_dname_free(&dname, NULL);
                 free(k);
             } else {
                 add_tail(&new_config->keys, &k->n);
             }
         }
     }

     free($4.t);
     free(fqdn);
}

remote_start:
 | TEXT { conf_start_remote(scanner, $1.t); }
 | LOG_SRC  { conf_start_remote(scanner, strdup($1.t)); }
 | LOG  { conf_start_remote(scanner, strdup($1.t)); }
 | LOG_LEVEL  { conf_start_remote(scanner, strdup($1.t)); }
 | CONTROL    { conf_start_remote(scanner, strdup($1.t)); }
 ;

remote:
 | remote PORT NUM ';' {
     if (this_remote->addr.ss_family == AF_UNSPEC) {
       cf_error(scanner, "can't set port number before interface address\n");
     } else {
       sockaddr_port_set(&this_remote->addr, $3.i);
     }
   }
 | remote ADDRESS IPA ';' {
     conf_set_iface(scanner, &this_remote->addr, AF_INET, $3.t, CONFIG_DEFAULT_PORT);
     this_remote->prefix = IPV4_PREFIXLEN;
   }
 | remote ADDRESS IPA '/' NUM ';' {
     conf_set_iface(scanner, &this_remote->addr, AF_INET, $3.t, 0);
     SET_NUM(this_remote->prefix, $5.i, 0, IPV4_PREFIXLEN, "prefix length");
   }
 | remote ADDRESS IPA '@' NUM ';' {
     conf_set_iface(scanner, &this_remote->addr, AF_INET, $3.t, $5.i);
     this_remote->prefix = IPV4_PREFIXLEN;
   }
 | remote ADDRESS IPA6 ';' {
     conf_set_iface(scanner, &this_remote->addr, AF_INET6, $3.t, CONFIG_DEFAULT_PORT);
     this_remote->prefix = IPV6_PREFIXLEN;
   }
 | remote ADDRESS IPA6 '/' NUM ';' {
     conf_set_iface(scanner, &this_remote->addr, AF_INET6, $3.t, 0);
     SET_NUM(this_remote->prefix, $5.i, 0, IPV6_PREFIXLEN, "prefix length");
   }
 | remote ADDRESS IPA6 '@' NUM ';' {
     conf_set_iface(scanner, &this_remote->addr, AF_INET6, $3.t, $5.i);
     this_remote->prefix = IPV6_PREFIXLEN;
   }
 | remote KEY TEXT ';' {
     if (this_remote->key != 0) {
       cf_error(scanner, "only one TSIG key definition is allowed in remote section\n");
     } else {
        conf_key_add(scanner, &this_remote->key, $3.t);
     }
     free($3.t);
   }
 | remote VIA IPA ';' {
     conf_set_iface(scanner, &this_remote->via, AF_INET, $3.t, 0);
   }
 | remote VIA IPA6 ';' {
     conf_set_iface(scanner, &this_remote->via, AF_INET6, $3.t, 0);
   }
 | remote VIA TEXT ';' {
     conf_remote_set_via(scanner, $3.t);
     free($3.t);
   }
 ;

remotes:
   REMOTES '{'
 | remotes remote_start '{' remote '}' {
     if (this_remote->addr.ss_family == AF_UNSPEC) {
       cf_error(scanner, "remote '%s' has no defined address", this_remote->name);
     }
   }
 ;

group_member:
 TEXT { conf_add_member_into_group(scanner, $1.t); }
 ;

group:
 /* empty */
 | group_member
 | group ',' group_member
 ;

group_start:
 TEXT { conf_start_group(scanner, $1.t); }
 ;

groups:
   GROUPS '{'
 | groups group_start '{' group '}'
 ;

zone_acl_start:
   XFR_IN {
      this_list = &this_zone->acl.xfr_in;
   }
 | XFR_OUT {
      this_list = &this_zone->acl.xfr_out;
   }
 | NOTIFY_IN {
      this_list = &this_zone->acl.notify_in;
   }
 | NOTIFY_OUT {
      this_list = &this_zone->acl.notify_out;
   }
 | UPDATE_IN {
      this_list = &this_zone->acl.update_in;
 }
 ;

zone_acl_item:
 | TEXT { conf_acl_item(scanner, $1.t); }
 | LOG_SRC  { conf_acl_item(scanner, strdup($1.t)); }
 | LOG  { conf_acl_item(scanner, strdup($1.t)); }
 | LOG_LEVEL  { conf_acl_item(scanner, strdup($1.t)); }
 | CONTROL    { conf_acl_item(scanner, strdup($1.t)); }
 ;

zone_acl_list:
 | zone_acl_list zone_acl_item ','
 | zone_acl_list zone_acl_item ';'
 ;

zone_acl:
 | zone_acl TEXT ';' {
      /* Find existing node in remotes. */
      node_t* r = 0; conf_iface_t* found = 0;
      WALK_LIST (r, new_config->remotes) {
	 if (strcmp(((conf_iface_t*)r)->name, $2.t) == 0) {
	    found = (conf_iface_t*)r;
	    break;
	 }
      }

      /* Append to list if found. */
      if (!found) {
	 cf_error(scanner, "remote '%s' is not defined", $2.t);
      } else {
	 conf_remote_t *remote = malloc(sizeof(conf_remote_t));
	 if (!remote) {
	    cf_error(scanner, "out of memory");
	 } else {
	    remote->remote = found;
	    add_tail(this_list, &remote->n);
	 }
      }

      /* Free text token. */
      free($2.t);
   }
 ;

query_module:
 TEXT TEXT { query_module_create(scanner, $1.t, $2.t, true); free($1.t); free($2.t); }
 ;

query_module_list:
 | query_module ';' query_module_list
 ;

zone_start:
 | USER  { conf_zone_start(scanner, strdup($1.t)); }
 | REMOTES { conf_zone_start(scanner, strdup($1.t)); }
 | LOG_SRC { conf_zone_start(scanner, strdup($1.t)); }
 | LOG { conf_zone_start(scanner, strdup($1.t)); }
 | LOG_LEVEL { conf_zone_start(scanner, strdup($1.t)); }
 | CONTROL    { conf_zone_start(scanner, strdup($1.t)); }
 | NUM '/' TEXT {
    unsigned prefix_len = 0;
    SET_NUM(prefix_len, $1.i, 0, 255, "origin prefix length");
    size_t len = 3 + 1 + strlen($3.t) + 1; /* <0,255> '/' rest */
    char *name = malloc(len * sizeof(char));
    if (name == NULL) {
        cf_error(scanner, "out of memory");
    } else {
        name[0] = '\0';
        if (snprintf(name, len, "%u/%s", prefix_len, $3.t) < 0) {
            cf_error(scanner,"failed to convert rfc2317 origin to string");
        }
    }
    free($3.t);
    conf_zone_start(scanner, name);
 }
 | TEXT  { conf_zone_start(scanner, $1.t); }
 ;

zone:
   zone_start '{'
 | zone zone_acl_start '{' zone_acl '}'
 | zone zone_acl_start zone_acl_list
 | zone FILENAME TEXT ';' { this_zone->file = $3.t; }
 | zone BUILD_DIFFS BOOL ';' { this_zone->build_diffs = $3.i; }
 | zone SEMANTIC_CHECKS BOOL ';' { this_zone->enable_checks = $3.i; }
 | zone STORAGE TEXT ';' { this_zone->storage = $3.t; }
 | zone DNSSEC_KEYDIR TEXT ';' { this_zone->dnssec_keydir = $3.t; }
 | zone DISABLE_ANY BOOL ';' { this_zone->disable_any = $3.i; }
 | zone DBSYNC_TIMEOUT NUM ';' {
	SET_INT(this_zone->dbsync_timeout, $3.i, "zonefile-sync");
 }
 | zone DBSYNC_TIMEOUT INTERVAL ';' {
	SET_INT(this_zone->dbsync_timeout, $3.i, "zonefile-sync");
 }
 | zone IXFR_FSLIMIT SIZE ';' {
	SET_SIZE(new_config->ixfr_fslimit, $3.l, "ixfr-fslimit");
 }
 | zone IXFR_FSLIMIT NUM ';' {
	SET_SIZE(this_zone->ixfr_fslimit, $3.i, "ixfr-fslimit");
 }
 | zone NOTIFY_RETRIES NUM ';' {
	SET_NUM(this_zone->notify_retries, $3.i, 1, INT_MAX, "notify-retries");
   }
 | zone NOTIFY_TIMEOUT INTERVAL ';' {
	SET_NUM(this_zone->notify_timeout, $3.i, 1, INT_MAX, "notify-timeout");
   }
 | zone NOTIFY_TIMEOUT NUM ';' {
	SET_NUM(this_zone->notify_timeout, $3.i, 1, INT_MAX, "notify-timeout");
   }
 | zone DNSSEC_ENABLE BOOL ';' { this_zone->dnssec_enable = $3.i; }
 | zone SIGNATURE_LIFETIME NUM ';' {
	SET_NUM(this_zone->sig_lifetime, $3.i, 10800, INT_MAX, "signature-lifetime");
 }
 | zone SIGNATURE_LIFETIME INTERVAL ';' {
	SET_NUM(this_zone->sig_lifetime, $3.i, 10800, INT_MAX, "signature-lifetime");
 }
 | zone SERIAL_POLICY SERIAL_POLICY_VAL ';' {
	this_zone->serial_policy = $3.i;
 }
 | zone QUERY_MODULE '{' query_module_list '}'
 | zone REQ_EDNS_OPT NUM HEXSTR ';' {
     SET_UINT16(this_zone->req_edns_code, $3.i, "request-edns-option");
     this_zone->req_edns_data = $4.t;
     this_zone->req_edns_data_len = $4.l;
 }
 | zone REQ_EDNS_OPT NUM TEXT ';' {
     SET_UINT16(this_zone->req_edns_code, $3.i, "request-edns-option");
     this_zone->req_edns_data = $4.t;
     this_zone->req_edns_data_len = strlen(this_zone->req_edns_data);
 }
 ;

query_genmodule:
 TEXT TEXT { query_module_create(scanner, $1.t, $2.t, false); free($1.t); free($2.t); }
 ;
query_genmodule_list:
 | query_genmodule ';' query_genmodule_list
 ;

zones:
   ZONES '{'
 | zones zone '}'
 | zones DISABLE_ANY BOOL ';' { new_config->disable_any = $3.i; }
 | zones BUILD_DIFFS BOOL ';' { new_config->build_diffs = $3.i; }
 | zones SEMANTIC_CHECKS BOOL ';' { new_config->zone_checks = $3.i; }
 | zones IXFR_FSLIMIT SIZE ';' {
	SET_SIZE(new_config->ixfr_fslimit, $3.l, "ixfr-fslimit");
 }
 | zones IXFR_FSLIMIT NUM ';' {
	SET_SIZE(new_config->ixfr_fslimit, $3.i, "ixfr-fslimit");
 }
 | zones NOTIFY_RETRIES NUM ';' {
	SET_NUM(new_config->notify_retries, $3.i, 1, INT_MAX, "notify-retries");
   }
 | zones NOTIFY_TIMEOUT NUM ';' {
	SET_NUM(new_config->notify_timeout, $3.i, 1, INT_MAX, "notify-timeout");
   }
 | zones NOTIFY_TIMEOUT INTERVAL ';' {
	SET_NUM(new_config->notify_timeout, $3.i, 1, INT_MAX, "notify-timeout");
   }
 | zones DBSYNC_TIMEOUT NUM ';' {
	SET_NUM(new_config->dbsync_timeout, $3.i, 0, INT_MAX, "zonefile-sync");
 }
 | zones DBSYNC_TIMEOUT INTERVAL ';' {
	SET_NUM(new_config->dbsync_timeout, $3.i, 0, INT_MAX, "zonefile-sync");
 }
 | zones STORAGE TEXT ';' { new_config->storage = $3.t; }
 | zones TIMER_DB TEXT ';' { new_config->timer_db = $3.t; }
 | zones DNSSEC_ENABLE BOOL ';' { new_config->dnssec_enable = $3.i; }
 | zones DNSSEC_KEYDIR TEXT ';' { new_config->dnssec_keydir = $3.t; }
 | zones SIGNATURE_LIFETIME NUM ';' {
	SET_NUM(new_config->sig_lifetime, $3.i, 10800, INT_MAX, "signature-lifetime");
 }
 | zones SIGNATURE_LIFETIME INTERVAL ';' {
	SET_NUM(new_config->sig_lifetime, $3.i, 10800, INT_MAX, "signature-lifetime");
 }
 | zones SERIAL_POLICY SERIAL_POLICY_VAL ';' {
	new_config->serial_policy = $3.i;
 }
 | zones REQ_EDNS_OPT NUM HEXSTR ';' {
	SET_UINT16(new_config->req_edns_code, $3.i, "request-edns-option");
	new_config->req_edns_data = $4.t;
	new_config->req_edns_data_len = $4.l;
 }
 | zones REQ_EDNS_OPT NUM TEXT ';' {
	SET_UINT16(new_config->req_edns_code, $3.i, "request-edns-option");
	new_config->req_edns_data = $4.t;
 	new_config->req_edns_data_len = strlen(new_config->req_edns_data);
 }
 | zones QUERY_MODULE '{' query_genmodule_list '}'
 ;

log_prios_start: {
  this_logmap = malloc(sizeof(conf_log_map_t));
  this_logmap->source = 0;
  this_logmap->prios = 0;
  add_tail(&this_log->map, &this_logmap->n);
}
;

log_prios:
   log_prios_start
 | log_prios LOG_LEVEL ',' { this_logmap->prios |= $2.i;
	cf_warning(scanner, "multiple log severities are deprecated, "
	                    "using the least serious one");
 }
 | log_prios LOG_LEVEL ';' { this_logmap->prios |= $2.i; }
 ;

log_src:
 | log_src LOG_SRC log_prios {
     this_logmap->source = $2.i;
     this_logmap = 0;
   }
 ;

log_dest: LOG_DEST {
  /* Find already existing rule. */
  this_log = 0;
  node_t *n = 0;
  WALK_LIST(n, new_config->logs) {
    conf_log_t* log = (conf_log_t*)n;
    if (log->type == $1.i) {
      this_log = log;
      break;
    }
  }

  if (!this_log) {
    this_log = malloc(sizeof(conf_log_t));
    this_log->type = $1.i;
    this_log->file = 0;
    init_list(&this_log->map);
    add_tail(&new_config->logs, &this_log->n);
  }
}
;

log_file: FILENAME TEXT {
  /* Find already existing rule. */
  this_log = 0;
  node_t *n = 0;
  WALK_LIST(n, new_config->logs) {
    conf_log_t* log = (conf_log_t*)n;
    if (log->type == LOGT_FILE) {
      if (strcmp($2.t, log->file) == 0) {
        this_log = log;
	free($2.t);
        break;
      }
    }
  }

  /* Create new rule. */
  if (!this_log) {
    this_log = malloc(sizeof(conf_log_t));
    this_log->type = LOGT_FILE;
    this_log->file = strcpath($2.t);
    init_list(&this_log->map);
    add_tail(&new_config->logs, &this_log->n);
  }
}
;

log_end: {
}
;

log_start:
 | log_start log_dest '{' log_src '}'
 | log_start log_file '{' log_src '}'
 ;

log: LOG { } '{' log_start log_end
 ;

ctl_listen_start:
  LISTEN_ON { conf_init_iface(scanner, NULL); }
  ;

ctl_allow_start:
  ALLOW {
    this_list = &new_config->ctl.allow;
  }
  ;

control:
   CONTROL '{' { new_config->ctl.have = true; }
 | control ctl_listen_start '{' interface '}' {
     if (this_iface->addr.ss_family == AF_UNSPEC) {
       cf_error(scanner, "control interface has no defined address");
     } else {
       new_config->ctl.iface = this_iface;
     }
 }
 | control ctl_listen_start TEXT ';' {
     sockaddr_set(&this_iface->addr, AF_UNIX, $3.t, 0);
     new_config->ctl.iface = this_iface;
     free($3.t);
 }
 | control ctl_allow_start '{' zone_acl '}'
 | control ctl_allow_start zone_acl_list
 ;

conf: ';' | system '}' | interfaces '}' | keys '}' | remotes '}' | groups '}' | zones '}' | log '}' | control '}';

%%
