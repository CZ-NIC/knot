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
static conf_iface_t *this_iface;
static conf_zone_t *this_zone;

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

%token LOG LOG_DEST
%token <t> LOG_SRC
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

log_flags:
 | log_flags LOG_SRC LOG_LEVEL ';'
 ;

log_dest:
 | LOG_DEST '{' log_flags
 | FILENAME TEXT '{' log_flags
 ;

log:
   LOG '{'
 | log log_dest '}'
 ;

conf: ';' | system '}' | interfaces '}' | zones '}' | log '}';

%%
