/*!
 * \file zoneparser.h
 *
 * \author modifications by Jan Kadlec <jan.kadlec@nic.cz>, most of the code
 *         by NLnet Labs.
 *         Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *         See LICENSE for the license.
 *
 * \brief Zone compiler.
 *
 * \addtogroup zoneparser
 * @{
 */

#ifndef _KNOT_ZONEPARSER_H_
#define _KNOT_ZONEPARSER_H_

#include <stdio.h>

#include "dnslib/dname.h"
#include "dnslib/rrset.h"
#include "dnslib/node.h"
#include "dnslib/rdata.h"
#include "dnslib/zone.h"
#include "dnslib/dname-table.h"
#include "dnslib/dname-table.h"
#include "common/slab/slab.h"

#define MAXRDATALEN	64	/*!< Maximum number of RDATA items. */
#define MAXLABELLEN	63	/*!< Maximum label length. */
#define MAXDOMAINLEN	255	/*!< Maximum domain name length */
#define MAX_RDLENGTH	65535	/*!< Maximum length of RDATA item */
#define	MAXTOKENSLEN	512	/*!< Maximum number of tokens per entry. */
#define	B64BUFSIZE	65535	/*!< Buffer size for b64 conversion. */
#define	ROOT		(const uint8_t *)"\001" /*!< Root domain name. */

#define NSEC_WINDOW_COUNT     256	/*!< Number of NSEC windows. */
#define NSEC_WINDOW_BITS_COUNT 256	/*!< Number of bits in NSEC window. */
/*! \brief Size of NSEC window in bytes. */
#define NSEC_WINDOW_BITS_SIZE  (NSEC_WINDOW_BITS_COUNT / 8)

/*
 * RFC 4025 - codes for different types that IPSECKEY can hold.
 */
#define IPSECKEY_NOGATEWAY      0
#define IPSECKEY_IP4            1
#define IPSECKEY_IP6            2
#define IPSECKEY_DNAME          3

#define LINEBUFSZ 1024	/*!< Buffer size for one line in zone file. */

struct lex_data {
    size_t   len;		/*!< holds the label length */
    char    *str;		/*!< holds the data */
};

#define DEFAULT_TTL 3600

int yylex_destroy();

/*! \todo Implement ZoneDB. */
typedef void namedb_type;

/*!
 * \brief One-purpose linked list holding pointers to RRSets.
 */
struct rrset_list {
	dnslib_rrset_t *data; /*!< List data. */
	struct rrset_list *next; /*!< Next node. */
};

typedef struct rrset_list rrset_list_t;

/*!
 * \brief Main zoneparser structure.
 */
struct zparser {
	const char *filename; /*!< File with zone. */
	uint32_t default_ttl; /*!< Default TTL. */
	uint16_t default_class; /*!< Default class. */
	dnslib_zone_t *current_zone; /*!< Current zone. */
	dnslib_node_t *origin; /*!< Origin node. */
	dnslib_dname_t *prev_dname; /*!< Previous dname. */
	dnslib_node_t *default_apex; /*!< Zone default apex. */

	dnslib_dname_table_t *dname_table; /*!< Domain name table (AVL tree). */

	dnslib_node_t *last_node; /*!< Last processed node. */

	char *dname_str; /*!< Temporary dname. */

	int error_occurred; /*!< Error occured flag */
	unsigned int errors; /*!< Number of errors. */
	unsigned int line; /*!< Current line */

	dnslib_rrset_t *current_rrset; /*!< Current RRSet. */
	dnslib_rdata_item_t *temporary_items; /*!< Temporary rdata items. */

	/*!
	 * \brief list of RRSIGs that were not inside their nodes in zone file
	 */
	rrset_list_t *rrsig_orphans;

	dnslib_dname_t *root_domain; /*!< Root domain name. */
	slab_cache_t *parser_slab; /*!< Slab for parser. */
	rrset_list_t *node_rrsigs; /*!< List of RRSIGs in current node. */

	int rdata_count; /*!< Count of parsed rdata. */
};

typedef struct zparser zparser_type;

extern zparser_type *parser;

/* used in zonec.lex */
extern FILE *yyin;

int yyparse(void);

int yylex(void);

void yyrestart(FILE *);

/*!
 * \brief Does all the processing of RR - saves to zone, assigns RRSIGs etc.
 */
int process_rr();

/*!
 * \brief Converts hex text format to wireformat.
 *
 * \param hex String to be converted.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_hex(const char *hex, size_t len);

/*!
 * \brief Converts hex text format with length to wireformat.
 *
 * \param hex String to be converted/.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_hex_length(const char *hex, size_t len);

/*!
 * \brief Converts time string to wireformat.
 *
 * \param time Time string to be converted.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_time(const char *time);
/*!
 * \brief Converts a protocol and a list of service port numbers
 * (separated by spaces) in the rdata to wireformat
 *
 * \param protostr Protocol string.
 * \param servicestr Service string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_services(const char *protostr, char *servicestr);

/*!
 * \brief Converts serial to wireformat.
 *
 * \param serialstr Serial string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_serial(const char *serialstr);
/*!
 * \brief Converts period to wireformat.
 *
 * \param periodstr Period string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_period(const char *periodstr);

/*!
 * \brief Converts short int to wireformat.
 *
 * \param text String containing short int.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_short(const char *text);

/*!
 * \brief Converts long int to wireformat.
 *
 * \param text String containing long int.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_long(const char *text);

/*!
 * \brief Converts byte to wireformat.
 *
 * \param text String containing byte.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_byte(const char *text);

/*!
 * \brief Converts A rdata string to wireformat.
 *
 * \param text String containing A rdata.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_a(const char *text);

/*!
 * \brief Converts AAAA rdata string to wireformat.
 *
 * \param text String containing AAAA rdata.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_aaaa(const char *text);

/*!
 * \brief Converts text string to wireformat.
 *
 * \param text Text string.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_text(const char *text, size_t len);

/*!
 * \brief Converts domain name string to wireformat.
 *
 * \param name Domain name string.
 * \param len Length of string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_dns_name(const uint8_t* name, size_t len);

/*!
 * \brief Converts base32 encoded string to wireformat.
 * TODO consider replacing with our implementation.
 *
 * \param b32 Base32 encoded string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_b32(const char *b32);

/*!
 * \brief Converts base64 encoded string to wireformat.
 * TODO consider replacing with our implementation.
 *
 * \param b64 Base64 encoded string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_b64(const char *b64);

/*!
 * \brief Converts RR type string to wireformat.
 *
 * \param rr RR type string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_rrtype(const char *rr);

/*!
 * \brief Converts NXT string to wireformat.
 *
 * \param nxtbits NXT string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_nxt(uint8_t *nxtbits);

/*!
 * \brief Converts NSEC bitmap to wireformat.
 *
 * \param nsecbits[][] NSEC bits.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT]
					   [NSEC_WINDOW_BITS_SIZE]);
/*!
 * \brief Converts LOC string to wireformat.
 *
 * \param str LOC string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_loc(char *str);

/*!
 * \brief Converts algorithm string to wireformat.
 *
 * \param algstr Algorithm string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_algorithm(const char *algstr);

/*!
 * \brief Converts certificate type string to wireformat.
 *
 * \param typestr Certificate type mnemonic string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_certificate_type(const char *typestr);

/*!
 * \brief Converts APL data to wireformat.
 *
 * \param str APL data string.
 *
 * \return Converted wireformat.
 */
uint16_t *zparser_conv_apl_rdata(char *str);

/*!
 * \brief Parses unknown rdata.
 *
 * \param type Type of data.
 * \param wireformat Wireformat of data.
 *
 * \return Converted wireformat.
 */
void parse_unknown_rdata(uint16_t type, uint16_t *wireformat);

/*!
 * \brief Converts TTL string to int.
 *
 * \param ttlstr String
 * \param error Error code.
 *
 * \return Converted wireformat.
 */
uint32_t zparser_ttl2int(const char *ttlstr, int* error);

/*!
 * \brief Adds wireformat to temporary list of rdata items.
 *
 * \param data Wireformat to be added.
 */
void zadd_rdata_wireformat(uint16_t *data);

/*!
 * \brief Adds TXT wireformat to temporary list of rdata items.
 *
 * \param data Wireformat to be added.
 * \param first This is first text to be added.
 */
void zadd_rdata_txt_wireformat(uint16_t *data, int first);

/*!
 * \brief Cleans after using zadd_rdata_txt_wireformat().
 */
void zadd_rdata_txt_clean_wireformat();

/*!
 * \brief Adds domain name to temporary list of rdata items.
 *
 * \param domain Domain name to be added.
 */
void zadd_rdata_domain(dnslib_dname_t *domain);

/*!
 * \brief Sets bit in NSEC bitmap.
 *
 * \param bits[][] NSEC bitmaps.
 * \param index Index on which bit is to be set.
 */
void set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
		 uint16_t index);

/*!
 * \brief Allocate and init wireformat.
 *
 * \param data Data to be copied into newly created wireformat.
 * \param size Size of data.
 *
 * \return Allocated wireformat.
 */
uint16_t *alloc_rdata_init(const void *data, size_t size);

/*!
 * \brief Parses and creates zone from given file.
 *
 * \param name Origin domain name string.
 * \param zonefile File containing the zone.
 * \param outfile File to save dump of the zone to.
 * \param semantic_checks Enables or disables sematic checks.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int zone_read(const char *name, const char *zonefile, const char *outfile,
              int semantic_checks);

/*!
 * \brief Creates zparser instance.
 *
 *
 * \return Created zparser instance.
 */
zparser_type *zparser_create();

/*!
 * \brief Inits zoneparser structure.
 *
 * \param filename Name of file with zone.
 * \param ttl Default TTL.
 * \param rclass Default class.
 * \param origin Zone origin.
 */
void zparser_init(const char *filename, uint32_t ttl, uint16_t rclass,
		  dnslib_node_t *origin);

/*!
 * \brief Frees zoneparser structure.
 *
 */
void zparser_free();

int save_dnames_in_table(dnslib_dname_table_t *table,
                         dnslib_rrset_t *rrset);

#endif /* _KNOT_ZONEPARSER_H_ */

/*! @} */
