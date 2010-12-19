/*
 * zonec.h -- zone compiler.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _ZONEC_H_
#define _ZONEC_H_

#include <stdio.h>

#include "dname.h"
#include "rrset.h"
#include "node.h"
#include "rdata.h"
#include "rrsig.h"
#include "zone.h"

#define MAXRDATALEN	64
#define MAXLABELLEN	63
#define MAXDOMAINLEN	255
#define MAX_RDLENGTH	65535
#define	MAXTOKENSLEN	512		/* Maximum number of tokens per entry */
#define	B64BUFSIZE	65535		/* Buffer size for b64 conversion */
#define	ROOT		(const uint8_t *)"\001"

#define NSEC_WINDOW_COUNT     256
#define NSEC_WINDOW_BITS_COUNT 256
#define NSEC_WINDOW_BITS_SIZE  (NSEC_WINDOW_BITS_COUNT / 8)

#define IPSECKEY_NOGATEWAY      0       /* RFC 4025 */
#define IPSECKEY_IP4            1
#define IPSECKEY_IP6            2
#define IPSECKEY_DNAME          3

#define LINEBUFSZ 1024

struct lex_data {
    size_t   len;		/* holds the label length */
    char    *str;		/* holds the data */
};

#define DEFAULT_TTL 3600

/*! \todo Implement ZoneDB. */
typedef void namedb_type;

struct rrsig_list {
	dnslib_rrset_t *data;
	struct rrsig_list *next;
};

typedef struct rrsig_list rrsig_list_t;

/* administration struct */
typedef struct zparser zparser_type;
struct zparser {
	const char *filename;
	uint32_t default_ttl;
	uint16_t default_class;
	dnslib_zone_t *current_zone;
	dnslib_node_t *origin;
	dnslib_dname_t *prev_dname;
	dnslib_node_t *default_apex;

  dnslib_node_t *last_node;

	char *dname_str;

	int error_occurred;
	unsigned int errors;
	unsigned int line;

	unsigned int id;

//	curent rr will have to be represented as current rrset
//before:	rr_type current_rr;
	dnslib_rrset_t current_rrset; //XXX * was not there
	dnslib_rdata_item_t *temporary_items; //XXX only one * was there

	rrsig_list_t *rrsig_orphans;

	int rdata_count;
};

extern zparser_type *parser;

/* used in zonec.lex */
extern FILE *yyin;

int yyparse(void);
int yylex(void);
/*int yyerror(const char *s);*/
void yyrestart(FILE *);

int process_rr(void);
uint16_t *zparser_conv_hex(const char *hex, size_t len);
uint16_t *zparser_conv_hex_length(const char *hex, size_t len);
uint16_t *zparser_conv_time(const char *time);
uint16_t *zparser_conv_services(const char *protostr, char *servicestr);
uint16_t *zparser_conv_serial(const char *periodstr);
uint16_t *zparser_conv_period(const char *periodstr);
uint16_t *zparser_conv_short(const char *text);
uint16_t *zparser_conv_long(const char *text);
uint16_t *zparser_conv_byte(const char *text);
uint16_t *zparser_conv_a(const char *text);
uint16_t *zparser_conv_aaaa(const char *text);
uint16_t *zparser_conv_text(const char *text, size_t len);
uint16_t *zparser_conv_dns_name(const uint8_t* name, size_t len);
uint16_t *zparser_conv_b32(const char *b32);
uint16_t *zparser_conv_b64(const char *b64);
uint16_t *zparser_conv_rrtype(const char *rr);
uint16_t *zparser_conv_nxt(uint8_t nxtbits[]);
uint16_t *zparser_conv_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE]);
uint16_t *zparser_conv_loc(char *str);
uint16_t *zparser_conv_algorithm(const char *algstr);
uint16_t *zparser_conv_certificate_type(const char *typestr);
uint16_t *zparser_conv_apl_rdata(char *str);

void parse_unknown_rdata(uint16_t type, uint16_t *wireformat);

uint32_t zparser_ttl2int(const char *ttlstr, int* error);
void zadd_rdata_wireformat(uint16_t *data);
void zadd_rdata_txt_wireformat(uint16_t *data, int first);
void zadd_rdata_txt_clean_wireformat();
void zadd_rdata_domain(dnslib_dname_t *domain);

void set_bitnsec(uint8_t  bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
		 uint16_t index);

uint16_t *alloc_rdata_init(const void *data, size_t size);

void zone_read(char *name, const char *zonefile);

/* zparser.y */
zparser_type *zparser_create();
void zparser_init(const char *filename, uint32_t ttl, uint16_t rclass,
		  dnslib_node_t *origin);

#endif /* _ZONEC_H_ */
