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
/* Headers */
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include "common/sockaddr.h"
#include "libknot/dname.h"
#include "libknot/binary.h"
#include "knot/conf/conf.h"
#include "libknotd_la-cf-parse.h" /* Automake generated header. */

extern int cf_lex (YYSTYPE *lvalp, void *scanner);
extern void cf_error(void *scanner, const char *format, ...);
extern conf_t *new_config;
static conf_iface_t *this_iface = 0;
static conf_iface_t *this_remote = 0;
static conf_zone_t *this_zone = 0;
static conf_group_t *this_group = 0;
static list *this_list = 0;
static conf_log_t *this_log = 0;
static conf_log_map_t *this_logmap = 0;
//#define YYERROR_VERBOSE 1

static void conf_init_iface(void *scanner, char* ifname, int port)
{
   this_iface = malloc(sizeof(conf_iface_t));
   if (this_iface == NULL) {
      cf_error(scanner, "not enough memory when allocating interface");
      return;
   }
   memset(this_iface, 0, sizeof(conf_iface_t));
   this_iface->name = ifname;
   this_iface->port = port;
}

static void conf_start_iface(void *scanner, char* ifname)
{
   conf_init_iface(scanner, ifname, -1);
   add_tail(&new_config->ifaces, &this_iface->n);
   ++new_config->ifaces_count;
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
   sockaddr_init(&this_remote->via, -1);
   ++new_config->remotes_count;
}

static void conf_remote_set_via(void *scanner, char *item) {
   /* Find existing node in interfaces. */
   node* r = 0; conf_iface_t* found = 0;
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
      sockaddr_set(&this_remote->via, found->family, found->address, 0);
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
	node *n;
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
	// silently skip duplicates

	conf_remote_t *remote;
	WALK_LIST (remote, *this_list) {
		if (remote->remote == found) {
			return;
		}
	}

	// additional check for transfers

	if ((this_list == &this_zone->acl.xfr_in ||
	    this_list == &this_zone->acl.notify_out) && found->port == 0)
	{
		cf_error(scanner, "remote specified for XFR/IN or "
		"NOTIFY/OUT needs to have valid port!");
		return;
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

static int conf_key_exists(void *scanner, char *item)
{
    /* Find existing node in keys. */
    knot_dname_t *sample = knot_dname_new_from_str(item, strlen(item), 0);
    conf_key_t* r = 0;
    WALK_LIST (r, new_config->keys) {
        if (knot_dname_compare(r->k.name, sample) == 0) {
           cf_error(scanner, "key '%s' is already defined", item);
	   knot_dname_free(&sample);
           return 1;
        }
    }

    knot_dname_free(&sample);
    return 0;
}

static int conf_key_add(void *scanner, knot_tsig_key_t **key, char *item)
{
    /* Reset */
    *key = 0;

    /* Find in keys */
    knot_dname_t *sample = knot_dname_new_from_str(item, strlen(item), 0);

    conf_key_t* r = 0;
    WALK_LIST (r, new_config->keys) {
        if (knot_dname_compare(r->k.name, sample) == 0) {
           *key = &r->k;
           knot_dname_free(&sample);
           return 0;
        }
    }

    cf_error(scanner, "key '%s' is not defined", item);
    knot_dname_free(&sample);
    return 1;
}

static void conf_zone_start(void *scanner, char *name) {
   this_zone = malloc(sizeof(conf_zone_t));
   if (this_zone == NULL || name == NULL) {
      cf_error(scanner, "out of memory while allocating zone config");
      return;
   }
   memset(this_zone, 0, sizeof(conf_zone_t));
   this_zone->enable_checks = -1; // Default policy applies
   this_zone->notify_timeout = -1; // Default policy applies
   this_zone->notify_retries = 0; // Default policy applies
   this_zone->ixfr_fslimit = -1; // Default policy applies
   this_zone->dbsync_timeout = -1; // Default policy applies
   this_zone->disable_any = -1; // Default policy applies
   this_zone->build_diffs = -1; // Default policy applies

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

   /* Initialize ACL lists. */
   init_list(&this_zone->acl.xfr_in);
   init_list(&this_zone->acl.xfr_out);
   init_list(&this_zone->acl.notify_in);
   init_list(&this_zone->acl.notify_out);
   init_list(&this_zone->acl.update_in);

   /* Check domain name. */
   knot_dname_t *dn = NULL;
   if (this_zone->name != NULL) {
      dn = knot_dname_new_from_str(this_zone->name, nlen, 0);
   }
   if (dn == NULL) {
     free(this_zone->name);
     free(this_zone);
     this_zone = NULL;
     cf_error(scanner, "invalid zone origin");
   } else {
     /* Check for duplicates. */
     if (hattrie_tryget(new_config->names, (const char*)dn->name, dn->size) != NULL) {
           cf_error(scanner, "zone '%s' is already present, refusing to "
			     "duplicate", this_zone->name);
           knot_dname_free(&dn);
           free(this_zone->name);
           this_zone->name = NULL;
           /* Must not free, some versions of flex might continue after error and segfault.
            * free(this_zone); this_zone = NULL;
            */
           return;
     }

     /* Directly discard dname, won't be needed. */
     add_tail(&new_config->zones, &this_zone->n);
     *hattrie_get(new_config->names, (const char*)dn->name, dn->size) = (void *)1;
     ++new_config->zones_count;
     knot_dname_free(&dn);
   }
}

static int conf_mask(void* scanner, int nval, int prefixlen) {
    if (nval < 0 || nval > prefixlen) {
        cf_error(scanner, "IPv%c subnet prefix '%d' is out of range <0,%d>",
                 prefixlen == IPV4_PREFIXLEN ? '4' : '6', nval, prefixlen);
        return prefixlen; /* single host */
    }
    return nval;
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

%token <tok> SYSTEM IDENTITY HOSTNAME SVERSION NSID STORAGE KEY KEYS
%token <tok> TSIG_ALGO_NAME
%token <tok> WORKERS
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
%token <tok> RATE_LIMIT
%token <tok> RATE_LIMIT_SIZE
%token <tok> RATE_LIMIT_SLIP
%token <tok> TRANSFERS

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

config: conf_entries END { return 0; } ;

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
     if (this_iface->port > 0) {
       cf_error(scanner, "only one port definition is allowed in interface section\n");
     } else {
       this_iface->port = $3.i;
     }
   }
 | interface ADDRESS IPA ';' {
     if (this_iface->address != 0) {
       cf_error(scanner, "only one address is allowed in interface section\n");
     } else {
       this_iface->address = $3.t;
       this_iface->family = AF_INET;
     }
   }
 | interface ADDRESS IPA '@' NUM ';' {
     if (this_iface->address != 0) {
       cf_error(scanner, "only one address is allowed in interface section\n");
     } else {
       this_iface->address = $3.t;
       this_iface->family = AF_INET;
       if (this_iface->port > 0) {
	 cf_error(scanner, "only one port definition is allowed in interface section\n");
       } else {
	 this_iface->port = $5.i;
       }
     }
   }
 | interface ADDRESS IPA6 ';' {
     if (this_iface->address != 0) {
       cf_error(scanner, "only one address is allowed in interface section\n");
     } else {
       this_iface->address = $3.t;
       this_iface->family = AF_INET6;
     }
   }
 | interface ADDRESS IPA6 '@' NUM ';' {
     if (this_iface->address != 0) {
       cf_error(scanner, "only one address is allowed in interface section\n");
     } else {
       this_iface->address = $3.t;
       this_iface->family = AF_INET6;
       if (this_iface->port > 0) {
          cf_error(scanner, "only one port definition is allowed in interface section\n");
       } else {
          this_iface->port = $5.i;
       }
     }
   }
 ;

interfaces:
   INTERFACES '{'
 | interfaces interface_start '{' interface '}' {
   if (this_iface->address == 0) {
     cf_error(scanner, "interface '%s' has no defined address", this_iface->name);
   }
 }
 ;

system:
   SYSTEM '{'
 | system SVERSION TEXT ';' { new_config->version = $3.t; }
 | system IDENTITY TEXT ';' { new_config->identity = $3.t; }
 | system HOSTNAME TEXT ';' { new_config->hostname = $3.t; }
 | system NSID HEXSTR ';' { new_config->nsid = $3.t; new_config->nsid_len = $3.l; }
 | system NSID TEXT ';' { new_config->nsid = $3.t; new_config->nsid_len = strlen(new_config->nsid); }
 | system STORAGE TEXT ';' { new_config->storage = $3.t; }
 | system RUNDIR TEXT ';' { new_config->rundir = $3.t; }
 | system PIDFILE TEXT ';' {
      fprintf(stderr, "warning: Config option 'system.pidfile' is deprecated "
	         "and has no effect. Use 'rundir' instead.\n");
      free($3.t);
 }
 | system KEY TSIG_ALGO_NAME TEXT ';' {
     fprintf(stderr, "warning: Config option 'system.key' is deprecated "
		     "and has no effect.\n");
     free($4.t);
 }
 | system WORKERS NUM ';' {
     if ($3.i <= 0) {
        cf_error(scanner, "worker count must be greater than 0\n");
     } else {
        new_config->workers = $3.i;
     }
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
 | system MAX_CONN_IDLE INTERVAL ';' { new_config->max_conn_idle = $3.i; }
 | system MAX_CONN_HS INTERVAL ';' { new_config->max_conn_hs = $3.i; }
 | system MAX_CONN_REPLY INTERVAL ';' { new_config->max_conn_reply = $3.i; }
 | system RATE_LIMIT NUM ';' { new_config->rrl = $3.i; }
 | system RATE_LIMIT_SIZE SIZE ';' { new_config->rrl_size = $3.l; }
 | system RATE_LIMIT_SIZE NUM ';' { new_config->rrl_size = $3.i; }
 | system RATE_LIMIT_SLIP NUM ';' { new_config->rrl_slip = $3.i; }
 | system TRANSFERS NUM ';' { new_config->xfers = $3.i; }
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
	   fqdnl = 0;
	} else {
	   strncpy(tmpdn, fqdn, fqdnl);
	   strncat(tmpdn, ".", 1);
	   free(fqdn);
	   fqdn = tmpdn;
	   fqdnl = strlen(fqdn);
	}
     }

     if (fqdn != NULL && !conf_key_exists(scanner, fqdn)) {
         knot_dname_t *dname = knot_dname_new_from_str(fqdn, fqdnl, 0);
	 if (!dname) {
             cf_error(scanner, "key name '%s' not in valid domain name format",
		      fqdn);
	     free($4.t);
	 } else {
             knot_dname_to_lower(dname);
             conf_key_t *k = malloc(sizeof(conf_key_t));
             memset(k, 0, sizeof(conf_key_t));

             k->k.name = dname;
             k->k.algorithm = $3.alg;
             knot_binary_from_base64($4.t, &(k->k.secret));
	     free($4.t);
             add_tail(&new_config->keys, &k->n);
             ++new_config->key_count;
	 }
     } else {
         free($4.t);
     }

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
     if (this_remote->port != 0) {
       cf_error(scanner, "only one port definition is allowed in remote section\n");
     } else {
       this_remote->port = $3.i;
     }
   }
 | remote ADDRESS IPA ';' {
     if (this_remote->address != 0) {
       cf_error(scanner, "only one address is allowed in remote section\n");
     } else {
       this_remote->address = $3.t;
       this_remote->prefix = IPV4_PREFIXLEN;
       this_remote->family = AF_INET;
     }
   }
   | remote ADDRESS IPA '/' NUM ';' {
       if (this_remote->address != 0) {
         cf_error(scanner, "only one address is allowed in remote section\n");
       } else {
         this_remote->address = $3.t;
         this_remote->family = AF_INET;
         this_remote->prefix = conf_mask(scanner, $5.i, IPV4_PREFIXLEN);
       }
     }
 | remote ADDRESS IPA '@' NUM ';' {
     if (this_remote->address != 0) {
       cf_error(scanner, "only one address is allowed in remote section\n");
     } else {
       this_remote->address = $3.t;
       this_remote->family = AF_INET;
       this_remote->prefix = IPV4_PREFIXLEN;
       if (this_remote->port != 0) {
	 cf_error(scanner, "only one port definition is allowed in remote section\n");
       } else {
	 this_remote->port = $5.i;
       }
     }
   }
 | remote ADDRESS IPA6 ';' {
     if (this_remote->address != 0) {
       cf_error(scanner, "only one address is allowed in remote section\n");
     } else {
       this_remote->address = $3.t;
       this_remote->family = AF_INET6;
       this_remote->prefix = IPV6_PREFIXLEN;
     }
   }
   | remote ADDRESS IPA6 '/' NUM ';' {
       if (this_remote->address != 0) {
         cf_error(scanner, "only one address is allowed in remote section\n");
       } else {
         this_remote->address = $3.t;
         this_remote->family = AF_INET6;
         this_remote->prefix = conf_mask(scanner, $5.i, IPV6_PREFIXLEN);
       }
     }
 | remote ADDRESS IPA6 '@' NUM ';' {
     if (this_remote->address != 0) {
       cf_error(scanner, "only one address is allowed in remote section\n");
     } else {
       this_remote->address = $3.t;
       this_remote->family = AF_INET6;
       this_remote->prefix = IPV6_PREFIXLEN;
       if (this_remote->port != 0) {
	 cf_error(scanner, "only one port definition is allowed in remote section\n");
       } else {
	 this_remote->port = $5.i;
       }
     }
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
     sockaddr_set(&this_remote->via, AF_INET, $3.t, 0);
     free($3.t);
   }
 | remote VIA IPA6 ';' {
     sockaddr_set(&this_remote->via, AF_INET6, $3.t, 0);
     free($3.t);
   }
 | remote VIA TEXT ';' {
     conf_remote_set_via(scanner, $3.t);
     free($3.t);
   }
 ;

remotes:
   REMOTES '{'
 | remotes remote_start '{' remote '}' {
     if (this_remote->address == 0) {
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
      node* r = 0; conf_iface_t* found = 0;
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

zone_start:
 | USER  { conf_zone_start(scanner, strdup($1.t)); }
 | REMOTES { conf_zone_start(scanner, strdup($1.t)); }
 | LOG_SRC { conf_zone_start(scanner, strdup($1.t)); }
 | LOG { conf_zone_start(scanner, strdup($1.t)); }
 | LOG_LEVEL { conf_zone_start(scanner, strdup($1.t)); }
 | CONTROL    { conf_zone_start(scanner, strdup($1.t)); }
 | NUM '/' TEXT {
    if ($1.i < 0 || $1.i > 255) {
        cf_error(scanner, "rfc2317 origin prefix '%ld' out of bounds", $1.i);
    }
    size_t len = 3 + 1 + strlen($3.t) + 1; /* <0,255> '/' rest */
    char *name = malloc(len * sizeof(char));
    if (name == NULL) {
        cf_error(scanner, "out of memory");
    } else {
        name[0] = '\0';
        if (snprintf(name, len, "%ld/%s", $1.i, $3.t) < 0) {
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
 | zone DISABLE_ANY BOOL ';' { this_zone->disable_any = $3.i; }
 | zone DBSYNC_TIMEOUT NUM ';' { this_zone->dbsync_timeout = $3.i; }
 | zone DBSYNC_TIMEOUT INTERVAL ';' { this_zone->dbsync_timeout = $3.i; }
 | zone IXFR_FSLIMIT SIZE ';' { new_config->ixfr_fslimit = $3.l; }
 | zone IXFR_FSLIMIT NUM ';' { this_zone->ixfr_fslimit = $3.i; }
 | zone NOTIFY_RETRIES NUM ';' {
       if ($3.i < 1) {
	   cf_error(scanner, "notify retries must be positive integer");
       } else {
	   this_zone->notify_retries = $3.i;
       }
   }
 | zone NOTIFY_TIMEOUT NUM ';' {
	if ($3.i < 1) {
	   cf_error(scanner, "notify timeout must be positive integer");
       } else {
	   this_zone->notify_timeout = $3.i;
       }
   }
 ;

zones:
   ZONES '{'
 | zones zone '}'
 | zones DISABLE_ANY BOOL ';' { new_config->disable_any = $3.i; }
 | zones BUILD_DIFFS BOOL ';' { new_config->build_diffs = $3.i; }
 | zones SEMANTIC_CHECKS BOOL ';' { new_config->zone_checks = $3.i; }
 | zones IXFR_FSLIMIT SIZE ';' { new_config->ixfr_fslimit = $3.l; }
 | zones IXFR_FSLIMIT NUM ';' { new_config->ixfr_fslimit = $3.i; }
 | zones NOTIFY_RETRIES NUM ';' {
       if ($3.i < 1) {
	   cf_error(scanner, "notify retries must be positive integer");
       } else {
	   new_config->notify_retries = $3.i;
       }
   }
 | zones NOTIFY_TIMEOUT NUM ';' {
	if ($3.i < 1) {
	   cf_error(scanner, "notify timeout must be positive integer");
       } else {
	   new_config->notify_timeout = $3.i;
       }
   }
 | zones DBSYNC_TIMEOUT NUM ';' {
	if ($3.i < 1) {
	   cf_error(scanner, "zonefile sync timeout must be positive integer");
       } else {
	   new_config->dbsync_timeout = $3.i;
       }
 }
 | zones DBSYNC_TIMEOUT INTERVAL ';' { new_config->dbsync_timeout = $3.i; }
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
 | log_prios LOG_LEVEL ',' { this_logmap->prios |= $2.i; }
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
  node *n = 0;
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
    ++new_config->logs_count;
  }
}
;

log_file: FILENAME TEXT {
  /* Find already existing rule. */
  this_log = 0;
  node *n = 0;
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
    ++new_config->logs_count;
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

log: LOG '{' log_start log_end;

ctl_listen_start:
  LISTEN_ON { conf_init_iface(scanner, NULL, -1); }
  ;

ctl_allow_start:
  ALLOW {
    this_list = &new_config->ctl.allow;
  }
  ;

control:
   CONTROL '{' { new_config->ctl.have = true; }
 | control ctl_listen_start '{' interface '}' {
     if (this_iface->address == 0) {
       cf_error(scanner, "control interface has no defined address");
     } else {
       new_config->ctl.iface = this_iface;
     }
 }
 | control ctl_listen_start TEXT ';' {
     this_iface->address = $3.t;
     this_iface->family = AF_UNIX;
     this_iface->port = 0;
     new_config->ctl.iface = this_iface;
 }
 | control ctl_allow_start '{' zone_acl '}'
 | control ctl_allow_start zone_acl_list
 ;

conf: ';' | system '}' | interfaces '}' | keys '}' | remotes '}' | groups '}' | zones '}' | log '}' | control '}';

%%
