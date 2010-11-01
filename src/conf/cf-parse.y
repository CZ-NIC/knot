%{
/* Headers */
#include "conf.h"

static struct conf_interface *this_iface;
static struct conf_key *this_key;

%}

%union {
    char *t;
    int i;
    tsig_algo_name alg;
}

%token END INVALID_TOKEN
%token SYSTEM IDENTITY VERSION LOG
%token INTERFACES ADDRESS PORT
%token ALGORITHM SECRET
%token SERVERS KEYS KEY INTERFACE
%token <t> TEXT

%token <i> NUM
%token <alg> TSIG_ALGO_NAME

%%

config: conf_entries END { return 0; } ;

conf_entries:
 /* EMPTY */
 | conf_entries conf
 ;

interface_start: TEXT {
    this_iface = malloc(sizeof(struct conf_interface));
    this_iface->name = $1;
 }
 ;

interface:
   interface_start '{'
 | interface ADDRESS TEXT ';' { this_iface->address = $3; }
 | interface PORT NUM ';' { this_iface->port = $3; }
 ;

interfaces:
   INTERFACES '{'
 | interfaces interface '}'
 ;

key_start: TEXT {
  this_key = malloc(sizeof(struct conf_key));
  this_key->name = $1;
 }
 ;

key:
   key_start '{'
 | key ALGORITHM TSIG_ALGO_NAME ';' { this_key->algorithm = $3; }
 | key SECRET TEXT ';' { this_key->secret = $3; }
 ;

keys:
   KEYS '{'
 | keys key '}'
 ;

server_start: TEXT {
  this_server = malloc(sizeof(struct conf_server));
  this_server->name = $1;
 }
 ;

server:
   server_start '{'
 | server ADDRESS TEXT ';' { this_server->address = $3; }
 | server PORT NUM ';' { this_server->port = $3; }
 | server KEY TEXT ';' { this_server->key = $3; }
 | server INTERFACE TEXT ';' { this_server->interface = $3; }
 ;

servers:
   SERVERS '{'
 | servers server '}'
 ;

system:
   SYSTEM '{'
 | system VERSION TEXT ';' { c->version = $3; }
 | system IDENTITY TEXT ';' { c->identity = $3; }
 ;

conf: ';' | system '}' | interfaces '}' | keys '}' | servers '}';

%%
