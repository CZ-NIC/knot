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
#include "conf.h"

extern void cf_error(const char *msg);
extern config_t *new_config;
static conf_iface_t *this_iface = 0;
static conf_zone_t *this_zone = 0;
static conf_log_t *this_log = 0;
static conf_log_map_t *this_logmap = 0;

%}

%union {
    char *t;
    int i;
    tsig_alg_t alg;
}

%token END INVALID_TOKEN
%token <t> TEXT
%token <i> NUM

%token SYSTEM IDENTITY VERSION STORAGE KEY
%token <alg> TSIG_ALGO_NAME

%token ZONES FILENAME
%token <t> ZONE

%token INTERFACES ADDRESS PORT
%token <t> IPA

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
 }
 ;

interface:
   interface_start '{'
 | interface ADDRESS IPA ';' { this_iface->address = $3; }
 | interface PORT NUM ';' { this_iface->port = $3; }
 | interface ADDRESS IPA '@' NUM ';' {
     this_iface->address = $3;
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

zones:
   ZONES '{'
 | zones zone '}'
 ;

zone_start: ZONE {
    this_zone = malloc(sizeof(conf_zone_t));
    memset(this_zone, 0, sizeof(conf_zone_t));
    this_zone->name = $1;
    add_tail(&new_config->zones, &this_zone->n);
 }
 ;

zone:
   zone_start '{'
 | zone FILENAME TEXT ';' { this_zone->file = $3; }
 ;

log_levels_start: {
  this_logmap = malloc(sizeof(conf_log_map_t));
  this_logmap->source = 0;
  this_logmap->levels = 0;
  add_tail(&this_log->map, &this_logmap->n);
}
;

log_levels:
   log_levels_start
 | log_levels LOG_LEVEL ',' { this_logmap->levels |= $2; }
 | log_levels LOG_LEVEL ';' { this_logmap->levels |= $2; }
 ;

log_src:
 | log_src LOG_SRC log_levels {
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
    this_log->file = $2;
    init_list(&this_log->map);
    add_tail(&new_config->logs, &this_log->n);
    ++new_config->logs_count;
  }
}
;

log_end: {
   if (EMPTY_LIST(new_config->logs)) {
     //! \todo Initialize default log facilities, missing.
   }
}
;

log_start:
 | log_start log_dest '{' log_src '}'
 | log_start log_file '{' log_src '}'
 ;

log: LOG '{' log_start log_end;


conf: ';' | system '}' | interfaces '}' | zones '}' | log '}';

%%
