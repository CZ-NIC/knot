/*!
 * \file cf-parse.y
 *
 * \author Ondrej Sury <ondrej.sury@nic.cz>
 *
 * \brief Server configuration structures and API.
 */
%{
/* Headers */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dnslib/dname.h"
#include "knot/conf/conf.h"

extern int yylex (void);
extern void cf_error(const char *msg);
extern conf_t *new_config;
static conf_iface_t *this_iface = 0;
static conf_iface_t *this_remote = 0;
static conf_zone_t *this_zone = 0;
static list *this_list = 0;
static conf_log_t *this_log = 0;
static conf_log_map_t *this_logmap = 0;
//#define YYERROR_VERBOSE 1

%}

%locations

%union {
    char *t;
    int i;
    tsig_alg_t alg;
}

%token END INVALID_TOKEN
%token <t> TEXT
%token <i> NUM
%token <i> INTERVAL
%token <i> BOOL

%token SYSTEM IDENTITY VERSION STORAGE KEY
%token <alg> TSIG_ALGO_NAME

%token REMOTES

%token ZONES FILENAME
%token SEMANTIC_CHECKS
%token NOTIFY_RETRIES
%token NOTIFY_TIMEOUT
%token DBSYNC_TIMEOUT
%token IXFR_FSLIMIT
%token XFR_IN
%token XFR_OUT
%token NOTIFY_IN
%token NOTIFY_OUT

%token INTERFACES ADDRESS PORT
%token <t> IPA
%token <t> IPA6

%token LOG
%token <i> LOG_DEST
%token <i> LOG_SRC
%token <i> LOG_LEVEL

%%

config: conf_entries END { return 0; } ;

conf_entries:
 /* EMPTY */
 | conf_entries conf
 ;

interface_start: TEXT {
    this_iface = malloc(sizeof(conf_iface_t));
    memset(this_iface, 0, sizeof(conf_iface_t));
    this_iface->name = $1;
    this_iface->address = 0; // No default address (mandatory)
    this_iface->port = CONFIG_DEFAULT_PORT;
    add_tail(&new_config->ifaces, &this_iface->n);
    ++new_config->ifaces_count;
 }
 ;

interface:
   interface_start '{'
 | interface PORT NUM ';' { this_iface->port = $3; }
 | interface ADDRESS IPA ';' {
     this_iface->address = $3;
     this_iface->family = AF_INET;
   }
 | interface ADDRESS IPA '@' NUM ';' {
     this_iface->address = $3;
     this_iface->family = AF_INET;
     this_iface->port = $5;
   }
 | interface ADDRESS IPA6 ';' {
     this_iface->address = $3;
     this_iface->family = AF_INET6;
   }
 | interface ADDRESS IPA6 '@' NUM ';' {
     this_iface->address = $3;
     this_iface->family = AF_INET6;
     this_iface->port = $5;
   }
 ;

interfaces:
   INTERFACES '{'
 | interfaces interface '}'
 ;

system:
   SYSTEM '{'
 | system VERSION TEXT ';' { new_config->version = $3; }
 | system IDENTITY TEXT ';' { new_config->identity = $3; }
 | system STORAGE TEXT ';' { new_config->storage = $3; }
 | system KEY TSIG_ALGO_NAME TEXT ';' {
     new_config->key.algorithm = $3;
     new_config->key.secret = $4;
   }
 ;

remote_start: TEXT {
    this_remote = malloc(sizeof(conf_iface_t));
    memset(this_remote, 0, sizeof(conf_iface_t));
    this_remote->name = $1;
    this_remote->address = 0; // No default address (mandatory)
    this_remote->port = 0; // Port wildcard
    add_tail(&new_config->remotes, &this_remote->n);
    ++new_config->remotes_count;
 }
 ;

remote:
   remote_start '{'
 | remote PORT NUM ';' { this_remote->port = $3; }
 | remote ADDRESS IPA ';' {
     this_remote->address = $3;
     this_remote->family = AF_INET;
   }
 | remote ADDRESS IPA '@' NUM ';' {
     this_remote->address = $3;
     this_remote->family = AF_INET;
     this_remote->port = $5;
   }
 | remote ADDRESS IPA6 ';' {
     this_remote->address = $3;
     this_remote->family = AF_INET6;
   }
 | remote ADDRESS IPA6 '@' NUM ';' {
     this_remote->address = $3;
     this_remote->family = AF_INET6;
     this_remote->port = $5;
   }
 ;

remotes:
   REMOTES '{'
 | remotes remote '}'
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
 ;

zone_acl_item:
   TEXT {
      /* Find existing node in remotes. */
      node* r = 0; conf_iface_t* found = 0;
      WALK_LIST (r, new_config->remotes) {
         if (strcmp(((conf_iface_t*)r)->name, $1) == 0) {
            found = (conf_iface_t*)r;
            break;
         }
      }

      /* Append to list if found. */
     if (!found) {
        char buf[256];
        snprintf(buf, sizeof(buf), "remote '%s' is not defined", $1);
        cf_error(buf);
     } else {
        conf_remote_t *remote = malloc(sizeof(conf_remote_t));
        if (!remote) {
           cf_error("out of memory");
        } else {
           remote->remote = found;
           add_tail(this_list, &remote->n);
        }
     }

     /* Free text token. */
     free($1);
   }
 ;

zone_acl_list:
   zone_acl_start
 | zone_acl_list zone_acl_item ','
 | zone_acl_list zone_acl_item ';'
 ;

zone_acl:
   zone_acl_start '{'
 | zone_acl TEXT ';' {
      /* Find existing node in remotes. */
      node* r = 0; conf_iface_t* found = 0;
      WALK_LIST (r, new_config->remotes) {
	 if (strcmp(((conf_iface_t*)r)->name, $2) == 0) {
	    found = (conf_iface_t*)r;
	    break;
	 }
      }

      /* Append to list if found. */
      if (!found) {
	 char buf[256];
	 snprintf(buf, sizeof(buf), "remote '%s' is not defined", $2);
	 cf_error(buf);
      } else {
	 conf_remote_t *remote = malloc(sizeof(conf_remote_t));
	 if (!remote) {
	    cf_error("out of memory");
	 } else {
	    remote->remote = found;
	    add_tail(this_list, &remote->n);
	 }
      }

      /* Free text token. */
      free($2);
   }
 ;

zone_start: TEXT {
   this_zone = malloc(sizeof(conf_zone_t));
   memset(this_zone, 0, sizeof(conf_zone_t));
   this_zone->enable_checks = -1; // Default policy applies
   this_zone->notify_timeout = -1; // Default policy applies
   this_zone->notify_retries = -1; // Default policy applies
   this_zone->ixfr_fslimit = -1; // Default policy applies
   this_zone->dbsync_timeout = -1; // Default policy applies
   this_zone->name = $1;

   // Append mising dot to ensure FQDN
   size_t nlen = strlen(this_zone->name);
   if (this_zone->name[nlen - 1] != '.') {
     this_zone->name = realloc(this_zone->name, nlen + 1 + 1);
     strcat(this_zone->name, ".");
   }

   /* Check domain name. */
   dnslib_dname_t *dn = dnslib_dname_new_from_str(this_zone->name,
                                                  nlen + 1,
                                                  0);
   if (dn == 0) {
     free(this_zone->name);
     free(this_zone);
     cf_error("invalid zone origin");
   } else {
     /* Directly discard dname, won't be needed. */
     dnslib_dname_free(&dn);
     add_tail(&new_config->zones, &this_zone->n);
     ++new_config->zones_count;

     /* Initialize ACL lists. */
     init_list(&this_zone->acl.xfr_in);
     init_list(&this_zone->acl.xfr_out);
     init_list(&this_zone->acl.notify_in);
     init_list(&this_zone->acl.notify_out);
   }  
 }
 ;

zone:
   zone_start '{'
 | zone zone_acl '}'
 | zone zone_acl_list
 | zone FILENAME TEXT ';' { this_zone->file = $3; }
 | zone SEMANTIC_CHECKS BOOL ';' { this_zone->enable_checks = $3; }
 | zone DBSYNC_TIMEOUT NUM ';' { this_zone->dbsync_timeout = $3; }
 | zone DBSYNC_TIMEOUT INTERVAL ';' { this_zone->dbsync_timeout = $3; }
 | zone IXFR_FSLIMIT NUM ';' { this_zone->ixfr_fslimit = $3; }
 | zone IXFR_FSLIMIT NUM 'k' ';' { this_zone->ixfr_fslimit = $3 * 1024; } // kB
 | zone IXFR_FSLIMIT NUM 'M' ';' { this_zone->ixfr_fslimit = $3 * 1048576; } // MB
 | zone IXFR_FSLIMIT NUM 'G' ';' { this_zone->ixfr_fslimit = $3 * 1073741824; } // GB
 | zone NOTIFY_RETRIES NUM ';' {
       if ($3 < 1) {
	   cf_error("notify retries must be positive integer");
       } else {
	   this_zone->notify_retries = $3;
       }
   }
 | zone NOTIFY_TIMEOUT NUM ';' {
	if ($3 < 1) {
	   cf_error("notify timeout must be positive integer");
       } else {
	   this_zone->notify_timeout = $3;
       }
   }
 ;

zones:
   ZONES '{'
 | zones zone '}'
 | zones SEMANTIC_CHECKS BOOL ';' { new_config->zone_checks = $3; }
 | zones NOTIFY_RETRIES NUM ';' {
       if ($3 < 1) {
	   cf_error("notify retries must be positive integer");
       } else {
	   new_config->notify_retries = $3;
       }
   }
 | zones NOTIFY_TIMEOUT NUM ';' {
	if ($3 < 1) {
	   cf_error("notify timeout must be positive integer");
       } else {
	   new_config->notify_timeout = $3;
       }
   }
 | zones DBSYNC_TIMEOUT NUM ';' {
	if ($3 < 1) {
	   cf_error("zonefile sync timeout must be positive integer");
       } else {
	   new_config->dbsync_timeout = $3;
       }
 }
 | zones DBSYNC_TIMEOUT INTERVAL ';' { new_config->dbsync_timeout = $3; }
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
 | log_prios LOG_LEVEL ',' { this_logmap->prios |= $2; }
 | log_prios LOG_LEVEL ';' { this_logmap->prios |= $2; }
 ;

log_src:
 | log_src LOG_SRC log_prios {
     this_logmap->source = $2;
     this_logmap = 0;
   }
 ;

log_dest: LOG_DEST {
  /* Find already existing rule. */
  this_log = 0;
  node *n = 0;
  WALK_LIST(n, new_config->logs) {
    conf_log_t* log = (conf_log_t*)n;
    if (log->type == $1) {
      this_log = log;
      break;
    }
  }

  if (!this_log) {
    this_log = malloc(sizeof(conf_log_t));
    this_log->type = $1;
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
      if (strcmp($2, log->file) == 0) {
        this_log = log;
        free($2);
        break;
      }
    }
  }

  /* Create new rule. */
  if (!this_log) {
    this_log = malloc(sizeof(conf_log_t));
    this_log->type = LOGT_FILE;
    this_log->file = strcpath($2);
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


conf: ';' | system '}' | interfaces '}' | remotes '}' | zones '}' | log '}';

%%

