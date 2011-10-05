/*!
 * \file zcompile.c
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz> process_rr(), RRSIG handling and
 *         minor modifications. most of the code by NLnet Labs
 *         Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *         See LICENSE for the license.
 *
 * \brief Zone compiler.
 *
 * \addtogroup zoneparser
 * @{
 */

#include <config.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>

#include "common/base32hex.h"
#include "zcompile/zcompile.h"
#include "zcompile/parser-util.h"
#include "knot/zone/zone-dump-text.h"
#include "zparser.h"
#include "zcompile/zcompile-error.h"
#include "knot/zone/zone-dump.h"
#include "libknot/libknot.h"
#include "libknot/util/utils.h"

//#define DEBUG_UNKNOWN_RDATA

#ifdef DEBUG_UNKNOWN_RDATA
#define dbg_rdata(msg...) fprintf(stderr, msg)
#define DBG_RDATA(cmds) do { cmds } while (0)
#else
#define dbg_rdata(msg...)
#define DBG_RDATA(cmds)
#endif



#define IP6ADDRLEN	(128/8)
#define	NS_INT16SZ	2
#define NS_INADDRSZ 4
#define NS_IN6ADDRSZ 16
#define APL_NEGATION_MASK      0x80U
#define APL_LENGTH_MASK	       (~APL_NEGATION_MASK)

//#define ZP_DEBUG

#ifdef ZP_DEBUG
#define debug_zp(msg...) fprintf(stderr, msg)
#else
#define debug_zp(msg...)
#endif

/*!
 * \brief Return data of raw data item.
 *
 * \param item Item.
 * \return uint16_t * Raw data.
 */
static inline uint16_t * rdata_atom_data(knot_rdata_item_t item)
{
	return (uint16_t *)(item.raw_data + 1);
}

/*!
 * \brief Return type of RRSet covered by given RRSIG.
 *
 * \param rrset RRSIG.
 * \return uint16_t Type covered.
 */
static uint16_t rrsig_type_covered(knot_rrset_t *rrset)
{
	assert(rrset->rdata->items[0].raw_data[0] == sizeof(uint16_t));

	return ntohs(*(uint16_t *) rdata_atom_data(rrset->rdata->items[0]));
}

/*!
 * \brief Adds RRSet to list.
 *
 * \param head Head of list.
 * \param rrsig RRSet to be added.
 */
static int rrset_list_add(rrset_list_t **head, knot_rrset_t *rrsig)
{
	if (*head == NULL) {
		*head = malloc(sizeof(rrset_list_t));
		if (*head == NULL) {
			ERR_ALLOC_FAILED;
			return KNOTDZCOMPILE_ENOMEM;
		}
		(*head)->next = NULL;
		(*head)->data = rrsig;
	} else {
		rrset_list_t *tmp = malloc(sizeof(*tmp));
		if (tmp == NULL) {
			ERR_ALLOC_FAILED;
			return KNOTDZCOMPILE_ENOMEM;
		}
		tmp->next = *head;
		tmp->data = rrsig;
		*head = tmp;
	}

	return KNOTDZCOMPILE_EOK;
}

/*!
 * \brief Deletes RRSet list. Sets pointer to NULL.
 *
 * \param head Head of list to be deleted.
 */
static void rrset_list_delete(rrset_list_t **head)
{
	rrset_list_t *tmp;
	if (*head == NULL) {
		return;
	}

	while (*head != NULL) {
		tmp = *head;
		*head = (*head)->next;
		free(tmp);
	}

	*head = NULL;
}

/*!
 * \brief Checks if item contains domain.
 *
 * \param type Type of RRSet.
 * \param index Index to check.
 *
 * \return > 1 if item is domain, 0 otherwise.
 */
static inline int rdata_atom_is_domain(uint16_t type, size_t index)
{
	const knot_rrtype_descriptor_t *descriptor
	= knot_rrtype_descriptor_by_type(type);
	return (index < descriptor->length
		&& (descriptor->wireformat[index] ==
		KNOT_RDATA_WF_COMPRESSED_DNAME  ||
		descriptor->wireformat[index] ==
		KNOT_RDATA_WF_UNCOMPRESSED_DNAME));
}

/*!
 * \brief Returns which wireformat type is on given index.
 *
 * \param type Type of RRSet.
 * \param index Index.
 *
 * \return uint8_t Wireformat type.
 */
static inline uint8_t rdata_atom_wireformat_type(uint16_t type, size_t index)
{
	const knot_rrtype_descriptor_t *descriptor =
		knot_rrtype_descriptor_by_type(type);
	assert(index < descriptor->length);
	return descriptor->wireformat[index];
}

/*!
 * \brief Converts rdata wireformat to rdata items.
 *
 * \param wireformat Wireformat/.
 * \param rrtype RR type.
 * \param data_size Size of wireformat.
 * \param items created rdata items.
 *
 * \return Number of items converted.
 */
static ssize_t rdata_wireformat_to_rdata_atoms(const uint16_t *wireformat,
					uint16_t rrtype,
					const uint16_t data_size,
					knot_rdata_item_t **items)
{
	dbg_rdata("read length: %d\n", data_size);
	uint16_t const *end = (uint16_t *)((uint8_t *)wireformat + (data_size));
	dbg_rdata("set end pointer: %p which means length: %d\n", end,
	          (uint8_t *)end - (uint8_t *)wireformat);
	size_t i;
	knot_rdata_item_t *temp_rdatas =
		malloc(sizeof(*temp_rdatas) * MAXRDATALEN);
	if (temp_rdatas == NULL) {
		ERR_ALLOC_FAILED;
		return KNOTDZCOMPILE_ENOMEM;
	}
	memset(temp_rdatas, 0, sizeof(*temp_rdatas) * MAXRDATALEN);

	knot_rrtype_descriptor_t *descriptor =
		knot_rrtype_descriptor_by_type(rrtype);

	assert(descriptor->length <= MAXRDATALEN);

	dbg_rdata("will be parsing %d items, total size: %d\n",
	          descriptor->length, data_size);

	for (i = 0; i < descriptor->length; ++i) {
		int is_domain = 0;
		int is_normalized = 0;
		int is_wirestore = 0;
		size_t length = 0;
		length = 0;
		int required = descriptor->length;

		switch (rdata_atom_wireformat_type(rrtype, i)) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
			is_domain = 1;
			is_normalized = 1;
			break;
		case KNOT_RDATA_WF_LITERAL_DNAME:
			is_domain = 1;
			is_wirestore = 1;
			break;
		case KNOT_RDATA_WF_BYTE:
			length = sizeof(uint8_t);
			break;
		case KNOT_RDATA_WF_SHORT:
			length = sizeof(uint16_t);
			break;
		case KNOT_RDATA_WF_LONG:
			length = sizeof(uint32_t);
			break;
		case KNOT_RDATA_WF_TEXT:
		case KNOT_RDATA_WF_BINARYWITHLENGTH:
			/* Length is stored in the first byte.  */
			length = 1;
			if ((uint8_t *)wireformat + length <= (uint8_t *)end) {
			//	length += wireformat[length - 1];
				length += *((uint8_t *)wireformat);
				dbg_rdata("%d: set new length: %d\n", i,
				          length);
			}
			/*if (buffer_position(packet) + length <= end) {
			length += buffer_current(packet)[length - 1];
			}*/
			break;
		case KNOT_RDATA_WF_A:
			length = sizeof(in_addr_t);
			break;
		case KNOT_RDATA_WF_AAAA:
			length = IP6ADDRLEN;
			break;
		case KNOT_RDATA_WF_BINARY:
			/* Remaining RDATA is binary.  */
			dbg_rdata("%d: guessing length from pointers: %p %p\n",
			          i,
			          wireformat, end);
			length = (uint8_t *)end - (uint8_t *)wireformat;
//			length = end - buffer_position(packet);
			break;
		case KNOT_RDATA_WF_APL:
			length = (sizeof(uint16_t)    /* address family */
				  + sizeof(uint8_t)   /* prefix */
				  + sizeof(uint8_t)); /* length */
			if ((uint8_t *)wireformat + length <= (uint8_t *)end) {
				/* Mask out negation bit.  */
				length += (wireformat[length - 1]
					   & APL_LENGTH_MASK);
			}
			break;
		case KNOT_RDATA_WF_IPSECGATEWAY:
			switch (rdata_atom_data(temp_rdatas[1])[0]) {
			/* gateway type */
			default:
			case IPSECKEY_NOGATEWAY:
				length = 0;
				break;
			case IPSECKEY_IP4:
				length = 4;
				break;
			case IPSECKEY_IP6:
				length = IP6ADDRLEN;
				break;
			case IPSECKEY_DNAME:
				is_domain = 1;
				is_normalized = 1;
				is_wirestore = 1;
				break;
			}
			break;
		}

		if (is_domain) {
			knot_dname_t *dname;

			if (!required && (wireformat == end)) {
				break;
			}

			dname = knot_dname_new_from_str((char *)wireformat,
							  length,
							  NULL);

			if (dname == NULL) {
				dbg_rdata("malformed dname!\n");
				/*! \todo rdata purge */
				free(temp_rdatas);
				return KNOTDZCOMPILE_EBRDATA;
			}
			dbg_rdata("%d: created dname: %s\n", i,
			          knot_dname_to_str(dname));

			if (is_wirestore) {
				/*temp_rdatas[i].raw_data =
					(uint16_t *) region_alloc(
				region, sizeof(uint16_t) + dname->name_size);
				temp_rdatas[i].data[0] = dname->name_size;
				memcpy(temp_rdatas[i].data+1, dname_name(dname),
				dname->name_size); */
				temp_rdatas[i].raw_data =
					malloc(sizeof(uint16_t) +
					       sizeof(uint8_t) * dname->size);
				if (temp_rdatas[i].raw_data == NULL) {
					ERR_ALLOC_FAILED;
					/*! \todo rdata purge */
					free(temp_rdatas);
					return KNOTDZCOMPILE_ENOMEM;
				}

				temp_rdatas[i].raw_data[0] = dname->size;
				memcpy(temp_rdatas[i].raw_data + 1,
				       dname->name, dname->size);

				knot_dname_release(dname);
			} else {
				temp_rdatas[i].dname = dname;
			}

		} else {
			dbg_rdata("%d :length: %d %d %p %p\n", i, length,
			          end - wireformat,
			          wireformat, end);
			if ((uint8_t *)wireformat + length > (uint8_t *)end) {
				if (required) {
					/* Truncated RDATA.  */
					/*! \todo rdata purge */
					free(temp_rdatas);
					dbg_rdata("truncated rdata\n");
					return KNOTDZCOMPILE_EBRDATA;
				} else {
					break;
				}
			}

			assert(wireformat <= end); /*!< \todo remove! */
			dbg_rdata("calling init with: %p and length : %d\n",
			          wireformat, length);
			temp_rdatas[i].raw_data = alloc_rdata_init(wireformat,
			                                           length);
			if (temp_rdatas[i].raw_data == NULL) {
				ERR_ALLOC_FAILED;
				/*! \todo rdata purge */
				free(temp_rdatas);
				return -1;
			}

//			temp_rdatas[i].raw_data[0] = length;
//			memcpy(temp_rdatas[i].raw_data + 1, wireformat, length);

/*			temp_rdatas[i].data = (uint16_t *) region_alloc(
				region, sizeof(uint16_t) + length);
				temp_rdatas[i].data[0] = length;
				buffer_read(packet,
					    temp_rdatas[i].data + 1, length); */
		}
		dbg_rdata("%d: adding length: %d (remaining: %d)\n", i, length,
		          (uint8_t *)end - ((uint8_t *)wireformat + length));
//		hex_print(temp_rdatas[i].raw_data + 1, length);
		wireformat = (uint16_t *)((uint8_t *)wireformat + length);
//		wireformat = wireformat + length;
		dbg_rdata("wire: %p\n", wireformat);
		dbg_rdata("remaining now: %d\n",
		          end - wireformat);

	}

	dbg_rdata("%p %p\n", wireformat, (uint8_t *)wireformat);

	if (wireformat < end) {
		/* Trailing garbage.  */
		dbg_rdata("w: %p e: %p %d\n", wireformat, end, end - wireformat);
//		region_destroy(temp_region);
		free(temp_rdatas);
		return KNOTDZCOMPILE_EBRDATA;
	}

	*items = temp_rdatas;
	/*	*rdatas = (rdata_atom_type *) region_alloc_init(
			region, temp_rdatas, i * sizeof(rdata_atom_type)); */
	return (ssize_t)i;
}

/* Taken from RFC 2535, section 7.  */
knot_lookup_table_t dns_algorithms[] = {
	{ 1, "RSAMD5" },	/* RFC 2537 */
	{ 2, "DH" },		/* RFC 2539 */
	{ 3, "DSA" },		/* RFC 2536 */
	{ 4, "ECC" },
	{ 5, "RSASHA1" },	/* RFC 3110 */
	{ 252, "INDIRECT" },
	{ 253, "PRIVATEDNS" },
	{ 254, "PRIVATEOID" },
	{ 0, NULL }
};

/* Taken from RFC 4398, section 2.1.  */
knot_lookup_table_t dns_certificate_types[] = {
	/*	0		Reserved */
	{ 1, "PKIX" },	/* X.509 as per PKIX */
	{ 2, "SPKI" },	/* SPKI cert */
	{ 3, "PGP" },	/* OpenPGP packet */
	{ 4, "IPKIX" },	/* The URL of an X.509 data object */
	{ 5, "ISPKI" },	/* The URL of an SPKI certificate */
	{ 6, "IPGP" },	/* The fingerprint and URL of an OpenPGP packet */
	{ 7, "ACPKIX" },	/* Attribute Certificate */
	{ 8, "IACPKIX" },	/* The URL of an Attribute Certificate */
	{ 253, "URI" },	/* URI private */
	{ 254, "OID" },	/* OID private */
	/*	255 		Reserved */
	/* 	256-65279	Available for IANA assignment */
	/*	65280-65534	Experimental */
	/*	65535		Reserved */
	{ 0, NULL }
};

/* Imported from lexer. */
extern int hexdigit_to_int(char ch);
extern FILE *zp_get_in(void *scanner);

/* Some global flags... */
static int vflag = 0;
/* if -v then print progress each 'progress' RRs */
static int progress = 10000;

/* Total errors counter */
static long int totalerrors = 0;
static long int totalrrs = 0;

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];
extern uint16_t nsec_highest_rcode;

/*!
 * \brief Allocate SIZE+sizeof(uint16_t) bytes and store SIZE in the first
 *        element.  Return a pointer to the allocation.
 *
 * \param size How many bytes to allocate.
 */
static uint16_t * alloc_rdata(size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	*result = size;
	return result;
}

uint16_t *alloc_rdata_init(const void *data, size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	if (result == NULL) {
		return NULL;
	}
	*result = size;
	memcpy(result + 1, data, size);
	return result;
}

/*
 * These are parser function for generic zone file stuff.
 */
uint16_t * zparser_conv_hex(const char *hex, size_t len)
{
	/* convert a hex value to wireformat */
	uint16_t *r = NULL;
	uint8_t *t;
	int i;

	if (len % 2 != 0) {
		zc_error_prev_line("number of hex digits "
		                   "must be a multiple of 2");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else if (len > MAX_RDLENGTH * 2) {
		zc_error_prev_line("hex data exceeds maximum rdata length (%d)",
			MAX_RDLENGTH);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		/* the length part */

		r = alloc_rdata(len / 2);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
		t = (uint8_t *)(r + 1);

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit((int)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					zc_error_prev_line(
						"illegal hex character '%c'",
						(int) *hex);
					parser->error_occurred =
						KNOTDZCOMPILE_EBRDATA;
					free(r);
					return NULL;
				}
				++hex;
			}
			++t;
		}
	}

	return r;
}

/* convert hex, precede by a 1-byte length */
uint16_t * zparser_conv_hex_length(const char *hex, size_t len)
{
	uint16_t *r = NULL;
	uint8_t *t;
	int i;
	if (len % 2 != 0) {
		zc_error_prev_line("number of hex digits must be a "
		                   "multiple of 2");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else if (len > 255 * 2) {
		zc_error_prev_line("hex data exceeds 255 bytes");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		uint8_t *l;

		/* the length part */
		r = alloc_rdata(len / 2 + 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}

		t = (uint8_t *)(r + 1);

		l = t++;
		*l = '\0';

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit((int)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					zc_error_prev_line(
						"illegal hex character '%c'",
						(int) *hex);
					parser->error_occurred =
						KNOTDZCOMPILE_EBRDATA;
					free(r);
					return NULL;
				}
				++hex;
			}
			++t;
			++*l;
		}
	}
	return r;
}

uint16_t * zparser_conv_time(const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;

	/* Try to scan the time... */
	if (!strptime(time, "%Y%m%d%H%M%S", &tm)) {
		zc_error_prev_line("date and time is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		uint32_t l = htonl(mktime_from_utc(&tm));
		r = alloc_rdata_init(&l, sizeof(l));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_services(const char *protostr, char *servicestr)
{
	/*
	 * Convert a protocol and a list of service port numbers
	 * (separated by spaces) in the rdata to wireformat
	 */
	uint16_t *r = NULL;
	uint8_t *p;
	uint8_t bitmap[65536/8];
	char sep[] = " ";
	char *word;
	int max_port = -8;
	/* convert a protocol in the rdata to wireformat */
	struct protoent *proto;

	memset(bitmap, 0, sizeof(bitmap));

	proto = getprotobyname(protostr);
	if (!proto) {
		proto = getprotobynumber(atoi(protostr));
	}
	if (!proto) {
		zc_error_prev_line("unknown protocol '%s'", protostr);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
		return NULL;
	}

	char *sp = 0;
	while ((word = strtok_r(servicestr, sep, &sp))) {
		struct servent *service;
		int port;

		service = getservbyname(word, proto->p_name);
		if (service) {
			/* Note: ntohs not ntohl!  Strange but true.  */
			port = ntohs((uint16_t) service->s_port);
		} else {
			char *end;
			port = strtol(word, &end, 10);
			if (*end != '\0') {
				zc_error_prev_line(
					"unknown service '%s' for"
					" protocol '%s'",
					word, protostr);
				parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
				continue;
			}
		}

		if (port < 0 || port > 65535) {
			zc_error_prev_line("bad port number %d", port);
		} else {
			set_bit(bitmap, port);
			if (port > max_port) {
				max_port = port;
			}
		}
	}

	r = alloc_rdata(sizeof(uint8_t) + max_port / 8 + 1);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	p = (uint8_t *)(r + 1);
	*p = proto->p_proto;
	memcpy(p + 1, bitmap, *r);

	return r;
}

uint16_t * zparser_conv_serial(const char *serialstr)
{
	uint16_t *r = NULL;
	uint32_t serial;
	const char *t;

	serial = strtoserial(serialstr, &t);
	if (*t != '\0') {
		zc_error_prev_line("serial is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		serial = htonl(serial);
		r = alloc_rdata_init(&serial, sizeof(serial));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_period(const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */
	uint16_t *r = NULL;
	uint32_t period;
	const char *end;

	/* Allocate required space... */
	period = strtottl(periodstr, &end);
	if (*end != '\0') {
		zc_error_prev_line("time period is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		period = htonl(period);
		r = alloc_rdata_init(&period, sizeof(period));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_short(const char *text)
{
	uint16_t *r = NULL;
	uint16_t value;
	char *end;

	value = htons((uint16_t) strtol(text, &end, 10));
	if (*end != '\0') {
		zc_error_prev_line("integer value is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_byte(const char *text)
{
	uint16_t *r = NULL;
	uint8_t value;
	char *end;

	value = (uint8_t) strtol(text, &end, 10);
	if (*end != '\0') {
		zc_error_prev_line("integer value is expected");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_algorithm(const char *text)
{
	const knot_lookup_table_t *alg;
	uint8_t id;

	alg = knot_lookup_by_name(dns_algorithms, text);
	if (alg) {
		id = (uint8_t) alg->id;
	} else {
		char *end;
		id = (uint8_t) strtol(text, &end, 10);
		if (*end != '\0') {
			zc_error_prev_line("algorithm is expected");
			parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
			return NULL;
		}
	}

	uint16_t *r = alloc_rdata_init(&id, sizeof(id));
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	return r;
}

uint16_t * zparser_conv_certificate_type(const char *text)
{
	/* convert a algoritm string to integer */
	const knot_lookup_table_t *type;
	uint16_t id;

	type = knot_lookup_by_name(dns_certificate_types, text);
	if (type) {
		id = htons((uint16_t) type->id);
	} else {
		char *end;
		id = htons((uint16_t) strtol(text, &end, 10));
		if (*end != '\0') {
			zc_error_prev_line("certificate type is expected");
			parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
			return NULL;
		}
	}

	uint16_t *r = alloc_rdata_init(&id, sizeof(id));
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	return r;
}

uint16_t * zparser_conv_a(const char *text)
{
	in_addr_t address;
	uint16_t *r = NULL;

	if (inet_pton(AF_INET, text, &address) != 1) {
		zc_error_prev_line("invalid IPv4 address '%s'", text);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(&address, sizeof(address));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}

	return r;
}

uint16_t * zparser_conv_aaaa(const char *text)
{
	uint8_t address[IP6ADDRLEN];
	uint16_t *r = NULL;

	if (inet_pton(AF_INET6, text, address) != 1) {
		zc_error_prev_line("invalid IPv6 address '%s'", text);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(address, sizeof(address));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_text(const char *text, size_t len)
{
	uint16_t *r = NULL;

	debug_zp("Converting text: %s\n", text);

	if (len > 255) {
		zc_error_prev_line("text string is longer than 255 characters,"
			" try splitting it into multiple parts");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		uint8_t *p;
		r = alloc_rdata(len + 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
		p = (uint8_t *)(r + 1);
		*p = len;
		memcpy(p + 1, text, len);
	}
	return r;
}

uint16_t * zparser_conv_dns_name(const uint8_t *name, size_t len)
{
	uint16_t *r = NULL;
	uint8_t *p = NULL;
	r = alloc_rdata(len);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}
	p = (uint8_t *)(r + 1);
	memcpy(p, name, len);

	return r;
}

uint16_t * zparser_conv_b32(const char *b32)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	size_t i = B64BUFSIZE - 1;

	if (strcmp(b32, "-") == 0) {
		r = alloc_rdata_init("", 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
		return r;
	}

	/*!< \todo BLEEDING EYES! */

	char b32_copy[strlen(b32) + 1];

	for (int i = 0; i < strlen(b32); i++) {
		b32_copy[i] = toupper(b32[i]);
	}

	/*!< \todo BLEEDING EYES! */
	b32_copy[strlen(b32)] = '\0';

	if (!base32hex_decode(b32_copy,
	                      strlen(b32_copy), (char *)buffer + 1, &i)) {
		zc_error_prev_line("invalid base32 data");
		parser->error_occurred = 1;
	} else {
		buffer[0] = i; /* store length byte */
		r = alloc_rdata_init(buffer, i + 1);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_b64(const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	int i;

	i = b64_pton(b64, buffer, B64BUFSIZE);
	if (i == -1) {
		zc_error_prev_line("invalid base64 data\n");
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		r = alloc_rdata_init(buffer, i);
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_rrtype(const char *text)
{
	uint16_t *r = NULL;
	uint16_t type = knot_rrtype_from_string(text);

	if (type == 0) {
		zc_error_prev_line("unrecognized RR type '%s'", text);
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
	} else {
		type = htons(type);
		r = alloc_rdata_init(&type, sizeof(type));
		if (r == NULL) {
			ERR_ALLOC_FAILED;
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
			return NULL;
		}
	}
	return r;
}

uint16_t * zparser_conv_nxt(uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t i;
	uint16_t last = 0;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0) {
			last = i + 1;
		}
	}

	uint16_t *r = alloc_rdata_init(nxtbits, last);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		return NULL;
	}

	return r;
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
uint16_t * zparser_conv_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT]
					     [NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i, j;
	uint16_t window_count = 0;
	uint16_t total_size = 0;
	uint16_t window_max = 0;

	/* The used windows.  */
	int used[NSEC_WINDOW_COUNT];
	/* The last byte used in each the window.  */
	int size[NSEC_WINDOW_COUNT];

	window_max = 1 + (nsec_highest_rcode / 256);

	/* used[i] is the i-th window included in the nsec
	 * size[used[0]] is the size of window 0
	 */

	/* walk through the 256 windows */
	for (i = 0; i < window_max; ++i) {
		int empty_window = 1;
		/* check each of the 32 bytes */
		for (j = 0; j < NSEC_WINDOW_BITS_SIZE; ++j) {
			if (nsecbits[i][j] != 0) {
				size[i] = j + 1;
				empty_window = 0;
			}
		}
		if (!empty_window) {
			used[window_count] = i;
			window_count++;
		}
	}

	for (i = 0; i < window_count; ++i) {
		total_size += sizeof(uint16_t) + size[used[i]];
	}

	r = alloc_rdata(total_size);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		parser->error_occurred = KNOTDZCOMPILE_EBRDATA;
		return NULL;
	}
	ptr = (uint8_t *)(r + 1);

	/* now walk used and copy it */
	for (i = 0; i < window_count; ++i) {
		ptr[0] = used[i];
		ptr[1] = size[used[i]];
		memcpy(ptr + 2, &nsecbits[used[i]], size[used[i]]);
		ptr += size[used[i]] + 2;
	}

	return r;
}

/* Parse an int terminated in the specified range. */
static int parse_int(const char *str,
	  char **end,
	  int *result,
	  const char *name,
	  int min,
	  int max)
{
	*result = (int) strtol(str, end, 10);
	if (*result < min || *result > max) {
		zc_error_prev_line("%s must be within the range [%d .. %d]",
			name,
			min,
			max);
		return 0;
	} else {
		return 1;
	}
}

/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				      1000000, 10000000, 100000000, 1000000000
				     };

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t precsize_aton(char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit((int)*cp)) {
		mval = mval * 10 + hexdigit_to_int(*cp++);
	}

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit((int)*cp)) {
			cmval = hexdigit_to_int(*cp++) * 10;
			if (isdigit((int)*cp)) {
				cmval += hexdigit_to_int(*cp++);
			}
		}
	}

	if (mval >= poweroften[7]) {
		/* integer overflow possible for *100 */
		mantissa = mval / poweroften[7];
		exponent = 9; /* max */
	} else {
		cmval = (mval * 100) + cmval;

		for (exponent = 0; exponent < 9; exponent++)
			if (cmval < poweroften[exponent+1]) {
				break;
			}

		mantissa = cmval / poweroften[exponent];
	}
	if (mantissa > 9) {
		mantissa = 9;
	}

	retval = (mantissa << 4) | exponent;

	if (*cp == 'm') {
		cp++;
	}

	*endptr = cp;

	return (retval);
}

/*
 * Parses a specific part of rdata.
 *
 * Returns:
 *
 *	number of elements parsed
 *	zero on error
 *
 */
uint16_t * zparser_conv_loc(char *str)
{
	uint16_t *r;
	uint32_t *p;
	int i;
	int deg, min, secs;	/* Secs is stored times 1000.  */
	uint32_t lat = 0, lon = 0, alt = 0;
	/* encoded defaults: version=0 sz=1m hp=10000m vp=10m */
	uint8_t vszhpvp[4] = {0, 0x12, 0x16, 0x13};
	char *start;
	double d;

	for (;;) {
		deg = min = secs = 0;

		/* Degrees */
		if (*str == '\0') {
			zc_error_prev_line("unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180)) {
			return NULL;
		}
		if (!isspace((int)*str)) {
			zc_error_prev_line("space expected after degrees");
			return NULL;
		}
		++str;

		/* Minutes? */
		if (isdigit((int)*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60)) {
				return NULL;
			}
			if (!isspace((int)*str)) {
				zc_error_prev_line("space expected after minutes");
				return NULL;
			}
			++str;
		}

		/* Seconds? */
		if (isdigit((int)*str)) {
			start = str;
			if (!parse_int(str, &str, &i, "seconds", 0, 60)) {
				return NULL;
			}

			if (*str == '.' && !parse_int(str + 1, &str, &i,
						      "seconds fraction",
						      0, 999)) {
				return NULL;
			}

			if (!isspace((int)*str)) {
				zc_error_prev_line("space expected after seconds");
				return NULL;
			}

			if (sscanf(start, "%lf", &d) != 1) {
				zc_error_prev_line("error parsing seconds");
			}

			if (d < 0.0 || d > 60.0) {
				zc_error_prev_line(
					"seconds not in range 0.0 .. 60.0");
			}

			secs = (int)(d * 1000.0 + 0.5);
			++str;
		}

		switch (*str) {
		case 'N':
		case 'n':
			lat = ((uint32_t)1 << 31) +
				(deg * 3600000 + min * 60000 + secs);
			break;
		case 'E':
		case 'e':
			lon = ((uint32_t)1 << 31) +
				(deg * 3600000 + min * 60000 + secs);
			break;
		case 'S':
		case 's':
			lat = ((uint32_t)1 << 31) -
				(deg * 3600000 + min * 60000 + secs);
			break;
		case 'W':
		case 'w':
			lon = ((uint32_t)1 << 31) -
				(deg * 3600000 + min * 60000 + secs);
			break;
		default:
			zc_error_prev_line(
				"invalid latitude/longtitude: '%c'", *str);
			return NULL;
		}
		++str;

		if (lat != 0 && lon != 0) {
			break;
		}

		if (!isspace((int)*str)) {
			zc_error_prev_line("space expected after"
				" latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		zc_error_prev_line("unexpected end of LOC data");
		return NULL;
	}

	if (!isspace((int)*str)) {
		zc_error_prev_line("space expected before altitude");
		return NULL;
	}
	++str;

	start = str;

	/* Sign */
	if (*str == '+' || *str == '-') {
		++str;
	}

	/* Meters of altitude... */
	int ret = strtol(str, &str, 10);
	UNUSED(ret); // Result checked in following switch

	switch (*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		if (!parse_int(str + 1, &str, &i, "altitude fraction", 0, 99)) {
			return NULL;
		}
		if (!isspace((int)*str) && *str != '\0' && *str != 'm') {
			zc_error_prev_line("altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		zc_error_prev_line("altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace((int)*str) && *str != '\0') {
		++str;
	}

	if (sscanf(start, "%lf", &d) != 1) {
		zc_error_prev_line("error parsing altitude");
	}

	alt = (uint32_t)(10000000.0 + d * 100 + 0.5);

	if (!isspace((int)*str) && *str != '\0') {
		zc_error_prev_line("unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for (i = 1; isspace((int)*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace((int)*str) && *str != '\0') {
			zc_error_prev_line("invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = alloc_rdata(16);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	p = (uint32_t *)(r + 1);

	memmove(p, vszhpvp, 4);
	write_uint32(p + 1, lat);
	write_uint32(p + 2, lon);
	write_uint32(p + 3, alt);

	return r;
}

/*
 * Convert an APL RR RDATA element.
 */
uint16_t * zparser_conv_apl_rdata(char *str)
{
	int negated = 0;
	uint16_t address_family;
	uint8_t prefix;
	uint8_t maximum_prefix;
	uint8_t length;
	uint8_t address[IP6ADDRLEN];
	char *colon = strchr(str, ':');
	char *slash = strchr(str, '/');
	int af;
	int rc;
	uint16_t rdlength;
	uint16_t *r;
	uint8_t *t;
	char *end;
	long p;

	if (!colon) {
		zc_error_prev_line("address family separator is missing");
		return NULL;
	}
	if (!slash) {
		zc_error_prev_line("prefix separator is missing");
		return NULL;
	}

	*colon = '\0';
	*slash = '\0';

	if (*str == '!') {
		negated = 1;
		++str;
	}

	if (strcmp(str, "1") == 0) {
		address_family = htons(1);
		af = AF_INET;
		length = sizeof(in_addr_t);
		maximum_prefix = length * 8;
	} else if (strcmp(str, "2") == 0) {
		address_family = htons(2);
		af = AF_INET6;
		length = IP6ADDRLEN;
		maximum_prefix = length * 8;
	} else {
		zc_error_prev_line("invalid address family '%s'", str);
		return NULL;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		zc_error_prev_line("invalid address '%s'", colon + 1);
		return NULL;
	} else if (rc == -1) {
		char ebuf[256];
		zc_error_prev_line("inet_pton failed: %s",
			strerror_r(errno, ebuf, sizeof(ebuf)));
		return NULL;
	}

	/* Strip trailing zero octets.	*/
	while (length > 0 && address[length - 1] == 0) {
		--length;
	}


	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		zc_error_prev_line("prefix not in the range 0 .. %d",
			maximum_prefix);
		return NULL;
	} else if (*end != '\0') {
		zc_error_prev_line("invalid prefix '%s'", slash + 1);
		return NULL;
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	r = alloc_rdata(rdlength);
	if (r == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	t = (uint8_t *)(r + 1);

	memcpy(t, &address_family, sizeof(address_family));
	t += sizeof(address_family);
	memcpy(t, &prefix, sizeof(prefix));
	t += sizeof(prefix);
	memcpy(t, &length, sizeof(length));
	if (negated) {
		*t |= APL_NEGATION_MASK;
	}
	t += sizeof(length);
	memcpy(t, address, length);

	return r;
}

/*
 * Below some function that also convert but not to wireformat
 * but to "normal" (int,long,char) types
 */

uint32_t zparser_ttl2int(const char *ttlstr, int *error)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	uint32_t ttl;
	const char *t;

	ttl = strtottl(ttlstr, &t);
	if (*t != 0) {
		zc_error_prev_line("invalid TTL value: %s", ttlstr);
		*error = 1;
	}

	return ttl;
}

void zadd_rdata_wireformat(uint16_t *data)
{
	parser->temporary_items[parser->rdata_count].raw_data = data;
	parser->rdata_count++;
}

/**
 * Used for TXT RR's to grow with undefined number of strings.
 */
void zadd_rdata_txt_wireformat(uint16_t *data, int first)
{
	debug_zp("Adding text!\n");
//	hex_print(data + 1, data[0]);
	knot_rdata_item_t *rd;

	/* First STR in str_seq, allocate 65K in first unused rdata
	 * else find last used rdata */
	if (first) {
		rd = &parser->temporary_items[parser->rdata_count];
//		if ((rd->data = (uint8_t *) region_alloc(parser->rr_region,
//			sizeof(uint8_t) + 65535 * sizeof(uint8_t))) == NULL) {
//			zc_error_prev_line("Could not allocate memory for TXT RR");
//			return;
//		}
		rd->raw_data = alloc_rdata(65535 * sizeof(uint8_t));
		if (rd->raw_data == NULL) {
			parser->error_occurred = KNOTDZCOMPILE_ENOMEM;
		}
		parser->rdata_count++;
		rd->raw_data[0] = 0;
	} else {
//		assert(0);
		rd = &parser->temporary_items[parser->rdata_count-1];
	}

	if ((size_t)rd->raw_data[0] + (size_t)data[0] > 65535) {
		zc_error_prev_line("too large rdata element");
		return;
	}

	memcpy((uint8_t *)rd->raw_data + 2 + rd->raw_data[0],
	       data + 1, data[0]);
	rd->raw_data[0] += data[0];
	free(data);
	debug_zp("Item after add\n");
//	hex_print(rd->raw_data + 1, rd->raw_data[0]);
}

void zadd_rdata_domain(knot_dname_t *dname)
{
	knot_dname_retain(dname);
//	printf("Adding rdata name: %s %p\n", dname->name, dname);
	parser->temporary_items[parser->rdata_count].dname = dname;
	parser->rdata_count++;
}

void parse_unknown_rdata(uint16_t type, uint16_t *wireformat)
{
	dbg_rdata("parsing unknown rdata for type: %d\n", type);
//	buffer_type packet;
	uint16_t size;
	ssize_t rdata_count;
	ssize_t i;
	knot_rdata_item_t *items = NULL;

	if (wireformat) {
		size = *wireformat;
	} else {
		return;
	}

//	buffer_create_from(&packet, wireformat + 1, *wireformat);
	rdata_count = rdata_wireformat_to_rdata_atoms(wireformat + 1, type,
						      size, &items);
//	dbg_rdata("got %d items\n", rdata_count);
	dbg_rdata("wf to items returned error: %s (%d)\n",
	          error_to_str(knot_zcompile_error_msgs, rdata_count),
	                       rdata_count);
	if (rdata_count < 0) {
		zc_error_prev_line("bad unknown RDATA\n");
		/*!< \todo leaks */
		return;
	}

	for (i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			zadd_rdata_domain(items[i].dname);
		} else {
			//XXX won't this create size two times?
			zadd_rdata_wireformat((uint16_t *)items[i].raw_data);
		}
	}
	free(items);
	/* Free wireformat */
	free(wireformat);
}

/*
 *
 * Opens a zone file.
 *
 * Returns:
 *
 *	- pointer to the parser structure
 *	- NULL on error and errno set
 *
 */
static int zone_open(const char *filename, uint32_t ttl, uint16_t rclass,
	  knot_node_t *origin, void *scanner)
{
	/* Open the zone file... */
	if (strcmp(filename, "-") == 0) {
		zp_set_in(stdin, scanner);
		filename = "<stdin>";
	} else {
		FILE *f = fopen(filename, "r");
		if (f == NULL) {
			return 0;
		}
		zp_set_in(f, scanner);
		if (zp_get_in(scanner) == 0) {
			return 0;
		}
	}

	int fd = fileno(zp_get_in(scanner));
	if (fd == -1) {
		return 0;
	}

//	if (fcntl(fd, F_SETLK, knot_file_lock(F_RDLCK, SEEK_SET)) == -1) {
//		fprintf(stderr, "Could not lock zone file for read!\n");
//		return 0;
//	}

	zparser_init(filename, ttl, rclass, origin);

	return 1;
}

void set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
	                uint16_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	uint8_t window = index / 256;
	uint8_t bit = index % 256;

	bits[window][bit / 8] |= (1 << (7 - bit % 8));
}

static int find_rrset_for_rrsig_in_zone(knot_zone_contents_t *zone,
                                        knot_rrset_t *rrsig)
{
	assert(rrsig != NULL);
	assert(rrsig->rdata->items[0].raw_data);

	knot_node_t *tmp_node = NULL;

	if (rrsig->type != KNOT_RRTYPE_NSEC3) {
		tmp_node = knot_zone_contents_get_node(zone, rrsig->owner);
	} else {
		tmp_node = knot_zone_contents_get_nsec3_node(zone,
						      rrsig->owner);
	}

	if (tmp_node == NULL) {
		return KNOTDZCOMPILE_EINVAL;
	}

	knot_rrset_t *tmp_rrset =
		knot_node_get_rrset(tmp_node, rrsig->type);

	if (tmp_rrset == NULL) {
		return KNOTDZCOMPILE_EINVAL;
	}

	if (tmp_rrset->rrsigs != NULL) {
		knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &tmp_node,
		                       KNOT_RRSET_DUPL_MERGE, 1);
		knot_rrset_free(&rrsig);
	} else {
		knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &tmp_node,
		                       KNOT_RRSET_DUPL_SKIP, 1);
	}

	return KNOTDZCOMPILE_EOK;
}

static int find_rrset_for_rrsig_in_node(knot_zone_contents_t *zone,
                                 knot_node_t *node,
                                 knot_rrset_t *rrsig)
{
	assert(rrsig != NULL);
	assert(rrsig->rdata->items[0].raw_data);
	assert(node);

	assert(knot_dname_compare(rrsig->owner, node->owner) == 0);

	knot_rrset_t *tmp_rrset =
		knot_node_get_rrset(node, rrsig_type_covered(rrsig));

	if (tmp_rrset == NULL) {
		return KNOTDZCOMPILE_EINVAL;
	}

	if (tmp_rrset->rrsigs != NULL) {
		if (knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &node,
		                           KNOT_RRSET_DUPL_MERGE, 1) < 0) {
			return KNOTDZCOMPILE_EINVAL;
		}
		knot_rrset_free(&rrsig);
	} else {
		if (knot_zone_contents_add_rrsigs(zone, rrsig, &tmp_rrset, &node,
		                           KNOT_RRSET_DUPL_SKIP, 1) < 0) {
			return KNOTDZCOMPILE_EINVAL;
		}
	}

	assert(tmp_rrset->rrsigs != NULL);

	return KNOTDZCOMPILE_EOK;
}

static knot_node_t *create_node(knot_zone_contents_t *zone,
	knot_rrset_t *current_rrset,
	int (*node_add_func)(knot_zone_contents_t *zone, knot_node_t *node,
	                     int create_parents, uint8_t, int),
	knot_node_t *(*node_get_func)(const knot_zone_contents_t *zone,
					const knot_dname_t *owner))
{
	knot_node_t *node =
		knot_node_new(current_rrset->owner, NULL, 0);
//	knot_dname_release(current_rrset->owner);
	if (node_add_func(zone, node, 1, 0, 1) != 0) {
		return NULL;
	}

	current_rrset->owner = node->owner;

	return node;
}

static void process_rrsigs_in_node(knot_zone_contents_t *zone,
                            knot_node_t *node)
{
	rrset_list_t *tmp = parser->node_rrsigs;
	while (tmp != NULL) {
		if (find_rrset_for_rrsig_in_node(zone, node,
						 tmp->data) != 0) {
			rrset_list_add(&parser->rrsig_orphans,
				       tmp->data);
		}
		tmp = tmp->next;
	}
}

int process_rr(void)
{
	knot_zone_t *zone = parser->current_zone;
	assert(zone != NULL);
	knot_zone_contents_t *contents = knot_zone_get_contents(zone);
	assert(contents != NULL);
	knot_rrset_t *current_rrset = parser->current_rrset;
	knot_rrset_t *rrset;
	knot_rrtype_descriptor_t *descriptor =
		knot_rrtype_descriptor_by_type(current_rrset->type);

	debug_zp("%s\n", knot_dname_to_str(parser->current_rrset->owner));
	debug_zp("type: %s\n", knot_rrtype_to_string(parser->current_rrset->type));
	debug_zp("rdata count: %d\n", parser->current_rrset->rdata->count);
//	hex_print(parser->current_rrset->rdata->items[0].raw_data,
//	          parser->current_rrset->rdata->items[0].raw_data[0]);

	if (descriptor->fixed_items) {
		assert(current_rrset->rdata->count == descriptor->length);
	}

	assert(current_rrset->rdata->count > 0);

	assert(knot_dname_is_fqdn(current_rrset->owner));

	int (*node_add_func)(knot_zone_contents_t *, knot_node_t *, int,
	                     uint8_t, int);
	knot_node_t *(*node_get_func)(const knot_zone_contents_t *,
	                                const knot_dname_t *);


	/* If we have RRSIG of NSEC3 type first node will have
	 * to be created in NSEC3 part of the zone */

	uint16_t type_covered = 0;
	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		type_covered = rrsig_type_covered(current_rrset);
	}

	if (current_rrset->type != KNOT_RRTYPE_NSEC3 &&
	    type_covered != KNOT_RRTYPE_NSEC3) {
		node_add_func = &knot_zone_contents_add_node;
		node_get_func = &knot_zone_contents_get_node;
	} else {
		node_add_func = &knot_zone_contents_add_nsec3_node;
		node_get_func = &knot_zone_contents_get_nsec3_node;
	}

	if ((current_rrset->type == KNOT_RRTYPE_SOA) && (zone != NULL)) {
		if (knot_node_rrset(knot_zone_contents_apex(contents),
		                      KNOT_RRTYPE_SOA) != NULL) {
			/* Receiving another SOA. */
			if (!knot_rrset_compare(current_rrset,
			    knot_node_rrset(knot_zone_contents_apex(contents),
			    KNOT_RRTYPE_SOA), KNOT_RRSET_COMPARE_WHOLE)) {
				return KNOTDZCOMPILE_ESOA;
			} else {
				zc_warning_prev_line("encountered identical "
				                     "extra SOA record");
				return KNOTDZCOMPILE_EOK;
			}
		}
	}

//TODO
/* Code from NSD */

	/* Make sure the maximum RDLENGTH does not exceed 65535 bytes.	*/
//	max_rdlength = rdata_maximum_wireformat_size(
//		descriptor, rr->rdata_count, rr->rdatas);

//	if (max_rdlength > MAX_RDLENGTH) {
//		zc_error_prev_line("maximum rdata length exceeds %d octets",
//		        MAX_RDLENGTH);
//		return 0;
//	}

	if (current_rrset->type == KNOT_RRTYPE_SOA) {
		if (knot_dname_compare(current_rrset->owner,
					 parser->origin->owner) != 0) {
			zc_error_prev_line("SOA record has a different "
				"owner than the one specified "
				"in config!\n");
			/* Such SOA cannot even be added, because
			 * it would not be in the zone apex. */
			return KNOTDZCOMPILE_EBADSOA;
		}
	}

	if (current_rrset->type == KNOT_RRTYPE_RRSIG) {
		/*!< \todo Still a leak somewhere. */
		knot_rrset_t *tmp_rrsig =
			knot_rrset_new(current_rrset->owner,
					     KNOT_RRTYPE_RRSIG,
					     current_rrset->rclass,
					     current_rrset->ttl);
//			knot_dname_release(current_rrset->owner);
		if (tmp_rrsig == NULL) {
			return KNOTDZCOMPILE_ENOMEM;
		}

		if (knot_rrset_add_rdata(tmp_rrsig,
		                           current_rrset->rdata) != 0) {
			return KNOTDZCOMPILE_EBRDATA;
		}

		if (parser->last_node &&
		    knot_dname_compare(parser->last_node->owner,
		                         current_rrset->owner) != 0) {
			/* RRSIG is first in the node, so we have to create it
			 * before we return
			 */
			if (parser->node_rrsigs != NULL) {
				process_rrsigs_in_node(contents,
				                       parser->last_node);
				rrset_list_delete(&parser->node_rrsigs);
			}

			if ((parser->last_node = create_node(contents,
						   current_rrset, node_add_func,
						   node_get_func)) == NULL) {
				knot_rrset_free(&tmp_rrsig);
				return KNOTDZCOMPILE_EBADNODE;
			}
		}

		if (rrset_list_add(&parser->node_rrsigs, tmp_rrsig) != 0) {
			return KNOTDZCOMPILE_ENOMEM;
		}

		return KNOTDZCOMPILE_EOK;
	}

	assert(current_rrset->type != KNOT_RRTYPE_RRSIG);

	knot_node_t *node = NULL;
	/* \note this could probably be much simpler */
	if (parser->last_node && current_rrset->type != KNOT_RRTYPE_SOA &&
	    knot_dname_compare(parser->last_node->owner,
				 current_rrset->owner) ==
	    0) {
		node = parser->last_node;
	} else {
		if (parser->last_node && parser->node_rrsigs) {
			process_rrsigs_in_node(contents,
			                       parser->last_node);
		}

		rrset_list_delete(&parser->node_rrsigs);

		/* new node */
		node = node_get_func(contents, current_rrset->owner);
	}

	if (node == NULL) {
		if (parser->last_node && parser->node_rrsigs) {
			process_rrsigs_in_node(contents,
			                       parser->last_node);
		}

		if ((node = create_node(contents, current_rrset,
					node_add_func,
					node_get_func)) == NULL) {
			return KNOTDZCOMPILE_EBADNODE;
		}
	}

	rrset = knot_node_get_rrset(node, current_rrset->type);
	if (!rrset) {
		rrset = knot_rrset_new(current_rrset->owner,
					 current_rrset->type,
					 current_rrset->rclass,
					 current_rrset->ttl);
		if (rrset == NULL) {
			return KNOTDZCOMPILE_ENOMEM;
		}

		if (knot_rrset_add_rdata(rrset, current_rrset->rdata) != 0) {
			free(rrset);
			return KNOTDZCOMPILE_EBRDATA;
		}

		/* I chose skip, but there should not really be
		 * any rrset to skip */
		if (knot_zone_contents_add_rrset(contents, rrset, &node,
		                   KNOT_RRSET_DUPL_SKIP, 1) < 0) {
			free(rrset);
			return KNOTDZCOMPILE_EBRDATA;
		}
	} else {
		if (current_rrset->type !=
				KNOT_RRTYPE_RRSIG && rrset->ttl !=
				current_rrset->ttl) {
			zc_error_prev_line(
				"TTL does not match the TTL of the RRset");
		}

		if (knot_zone_contents_add_rrset(contents, current_rrset,
		                          &node,
		                   KNOT_RRSET_DUPL_MERGE, 1) < 0) {
			free(rrset);
			return KNOTDZCOMPILE_EBRDATA;
		}

//		knot_dname_release(current_rrset->owner);

//		knot_rrset_merge((void *)&rrset, (void *)&current_rrset);

		/* TODO Search for possible duplicates... */
	}

/* \note DNAME and CNAME checks disabled - would slow things down a little
 * plus it cannot be done in the fashion below - we don't have information
 * about the length of rrset
 * Code from NSD
 */

//	if(current_rrset->type ==
//	   KNOT_RRTYPE_DNAME &&
//	   current_rrset->rdata->count > 1) {
//		zc_error_prev_line("multiple DNAMEs at the same name");
//	}
//	/* \note this actually counts items, not the legth we would need */
//	if(current_rrset->type ==
//	   KNOT_RRTYPE_CNAME &&
//	   current_rrset->rdata->count > 1) {
//		zc_error_prev_line("multiple CNAMEs at the same name");
//	/* \note this actually counts items, not the legth we would need */
//	}
//	if((current_rrset->type == KNOT_RRTYPE_DNAME &&
//	    knot_node_get_rrset(node, TYPE_CNAME)) ||
//	    (current_rrset->type == KNOT_RRTYPE_CNAME &&
//	    knot_node_get_rrset(node, TYPE_DNAME))) {
//		zc_error_prev_line("DNAME and CNAME at the same name");
//	}
//	/* \note we don't have similar function - maybe
//       * length of the skip_list
//       * should stay disabled
//	 */
//	if(domain_find_rrset(rr->owner, zone, TYPE_CNAME) &&
//		domain_find_non_cname_rrset(rr->owner, zone)) {
//		zc_error_prev_line("CNAME and other data at the same name");
//	}

	if (vflag > 1 && totalrrs > 0 && (totalrrs % progress == 0)) {
		zc_error_prev_line("Total errors: %ld\n", totalrrs);
	}

	parser->last_node = node;

	++totalrrs;

	return KNOTDZCOMPILE_EOK;
}

static uint find_rrsets_orphans(knot_zone_contents_t *zone, rrset_list_t
				*head)
{
	uint found_rrsets = 0;
	while (head != NULL) {
		if (find_rrset_for_rrsig_in_zone(zone, head->data) == 0) {
			found_rrsets += 1;
			debug_zp("RRSET succesfully found: owner %s type %s\n",
				 knot_dname_to_str(head->data->owner),
				 knot_rrtype_to_string(head->data->type));
		}
		else { /* we can throw it away now */
			knot_rrset_free(&head->data);
		}
		head = head->next;
	}
	return found_rrsets;
}

/*
 * Reads the specified zone into the memory
 *
 */
int zone_read(const char *name, const char *zonefile, const char *outfile,
	      int semantic_checks)
{
	if (!outfile) {
		zc_error_prev_line("Missing output file for '%s'\n",
			zonefile);
		return KNOTDZCOMPILE_EINVAL;
	}

//	char ebuf[256];

	knot_dname_t *dname =
		knot_dname_new_from_str(name, strlen(name), NULL);
	if (dname == NULL) {
		return KNOTDZCOMPILE_ENOMEM;
	}

	knot_node_t *origin_node = knot_node_new(dname, NULL, 0);

	//assert(origin_node->next == NULL);

	assert(knot_node_parent(origin_node, 0) == NULL);
	if (origin_node == NULL) {
		knot_dname_release(dname);
		return KNOTDZCOMPILE_ENOMEM;
	}

	void *scanner = NULL;
	zp_lex_init(&scanner);
	if (scanner == NULL) {
		return KNOTDZCOMPILE_ENOMEM;
	}

	if (!zone_open(zonefile, 3600, KNOT_CLASS_IN, origin_node, scanner)) {
		zc_error_prev_line("Cannot open '%s'\n",
			zonefile);
		zparser_free();
		return KNOTDZCOMPILE_EZONEINVAL;
	}

	if (zp_parse(scanner) != 0) {
		int fd = fileno(zp_get_in(scanner));
		if (fcntl(fd, F_SETLK,
		          knot_file_lock(F_UNLCK, SEEK_SET)) == -1) {
			return KNOTDZCOMPILE_EACCES;
		}

		FILE *in_file = (FILE *)zp_get_in(scanner);
		fclose(in_file);
		zp_lex_destroy(scanner);

		return KNOTDZCOMPILE_ESYNT;
	}

	knot_zone_contents_t *contents =
			knot_zone_get_contents(parser->current_zone);

	FILE *in_file = (FILE *)zp_get_in(scanner);
	fclose(in_file);
	zp_lex_destroy(scanner);

	/* Unlock zone file. */
//	int fd = fileno(zp_get_in(scanner));
//	if (fcntl(fd, F_SETLK, knot_file_lock(F_UNLCK, SEEK_SET)) == -1) {
//		fprintf(stderr, "Could not lock zone file for read!\n");
//		return 0;
//	}

	debug_zp("zp complete %p\n", parser->current_zone);

	if (parser->last_node && parser->node_rrsigs != NULL) {
		/* assign rrsigs to last node in the zone*/
		process_rrsigs_in_node(contents,
		                       parser->last_node);
		rrset_list_delete(&parser->node_rrsigs);
	}
	debug_zp("zone parsed\n");

	if (!(parser->current_zone &&
	      knot_node_rrset(parser->current_zone->contents->apex,
	                        KNOT_RRTYPE_SOA))) {
		zc_error_prev_line("Zone file does not contain SOA record!\n");
		knot_zone_deep_free(&parser->current_zone, 1, 1);
		zparser_free();
		return KNOTDZCOMPILE_EZONEINVAL;
	}

	uint found_orphans;
	found_orphans = find_rrsets_orphans(contents,
					    parser->rrsig_orphans);

	debug_zp("%u orphans found\n", found_orphans);
	/* List is no longer needed. */
	rrset_list_delete(&parser->rrsig_orphans);

	knot_zone_contents_adjust(contents);

	debug_zp("rdata adjusted\n");

	if (parser->errors != 0) {
		fprintf(stderr,
		        "Parser finished with error, not dumping the zone!\n");
	} else {
		knot_zdump_binary(contents,
		                    outfile, semantic_checks, zonefile);
		debug_zp("zone dumped.\n");
	}

	/* This is *almost* unnecessary */
	knot_zone_deep_free(&(parser->current_zone), 1, 1);

	fflush(stdout);
	totalerrors += parser->errors;
	zparser_free();

	return totalerrors;
}

//static void save_replace_dnames_in_rdata(knot_dname_table_t *table,
//					 knot_rdata_t *rdata, uint16_t type)
//{
//	assert(rdata && rdata->items);
//	const knot_rrtype_descriptor_t *desc =
//		knot_rrtype_descriptor_by_type(type);
//	assert(desc);

//	for (int i = 0; i < rdata->count; i++) {
//		if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
//		    desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
//		    desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME) {
//			/* See if dname is not in the table already. */
//			knot_dname_t *found_dname = NULL;
//			knot_dname_t *searched_dname = rdata->items[i].dname;
//			if ((found_dname =
//				knot_dname_table_find_dname(table,
//				searched_dname)) != NULL) {
//				knot_dname_free(&rdata->items[i].dname);
//				rdata->items[i].dname = found_dname;
//			} else {
//				if (knot_dname_table_add_dname(table,
//							        searched_dname)
//				   != 0) {
//					zc_error_prev_line(
//					        "Could not add name"
//					        "to table!\n");
//					return;
//				}
//			}
//		}
//	}
//}

//int save_dnames_in_table(knot_dname_table_t *table,
//			 knot_rrset_t *rrset)
//{
//	if (rrset == NULL) {
//		return KNOTDZCOMPILE_EINVAL;
//	}
//	/* Check and possibly delete the owner first */
//	knot_dname_t *found_dname = NULL;
//	if ((found_dname =
//		knot_dname_table_find_dname(table, rrset->owner)) != NULL &&
//		found_dname != rrset->owner) {
////		assert(rrset->owner != found_dname);
////		assert(found_dname->name != rrset->owner->name);
////		assert(found_dname->labels != rrset->owner->labels);
////		assert(rrset->owner != parser->last_node->owner);
////		assert(parser->last_node->owner != rrset->owner);
//		knot_dname_free(&rrset->owner);
//		/* owner is now a reference from the table */
//		rrset->owner = found_dname;
//		assert(parser->current_rrset->owner == rrset->owner);
//	} else if (found_dname != rrset->owner) {
//		/* Insert the dname in the table. */
//		if (knot_dname_table_add_dname(table, rrset->owner) != 0) {
//			return KNOTDZCOMPILE_ENOMEM;
//		}
//	}

//	knot_rdata_t *tmp_rdata = knot_rrset_get_rdata(rrset);

//	while (tmp_rdata->next != knot_rrset_rdata(rrset)) {
//		save_replace_dnames_in_rdata(table, tmp_rdata,
//					     knot_rrset_type(rrset));
//	}

//	save_replace_dnames_in_rdata(table, tmp_rdata,
//				     knot_rrset_type(rrset));

//	assert(rrset->owner != NULL);

//	return KNOTDZCOMPILE_EOK;
//}

/*! @} */
