/*
 * zonec.c -- zone compiler.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <assert.h>

#include "common.h"
#include "zonec.h"
#include "dnslib/dname.h"
#include "dnslib/rrset.h"
#include "dnslib/rdata.h"
#include "dnslib/node.h"
#include "dnslib/zone.h"
#include "dnslib/descriptor.h"
#include "parser-util.h"
#include "dnslib/debug.h"

#include "zparser.h"

#define IP6ADDRLEN	(128/8)
#define	NS_INT16SZ	2
#define NS_INADDRSZ 4
#define NS_IN6ADDRSZ 16
#define APL_NEGATION_MASK      0x80U

static inline uint8_t *
rdata_atom_data(dnslib_rdata_item_t item)
{
	return (uint8_t *) (item.raw_data + 1);
}

static inline int
rdata_atom_is_domain(uint16_t type, size_t index)
{
	const dnslib_rrtype_descriptor_t *descriptor
		= dnslib_rrtype_descriptor_by_type(type);
	return (index < descriptor->length
		&& (descriptor->wireformat[index] == DNSLIB_RDATA_WF_COMPRESSED_DNAME
		    || descriptor->wireformat[index] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME));
}

static inline uint8_t
rdata_atom_wireformat_type(uint16_t type, size_t index)
{
	const dnslib_rrtype_descriptor_t *descriptor
		= dnslib_rrtype_descriptor_by_type(type);
	assert(index < descriptor->length);
//	return (rdata_wireformat_type) descriptor->wireformat[index];
	return descriptor->wireformat[index];
}

ssize_t
rdata_wireformat_to_rdata_atoms(const uint16_t *wireformat, uint16_t rrtype,
                                const uint16_t data_size, dnslib_rdata_item_t *items)
{
//	size_t end = buffer_position(packet) + data_size;
	uint16_t const *end = wireformat + data_size; //XXX + 1?
	size_t i;
	dnslib_rdata_item_t temp_rdatas[MAXRDATALEN];
	dnslib_rrtype_descriptor_t *descriptor =
		dnslib_rrtype_descriptor_by_type(rrtype);

	assert(descriptor->length <= MAXRDATALEN);

/*	if (!buffer_available(packet, data_size)) {
		return -1;
	}*/

	for (i = 0; i < descriptor->length; ++i) {
		int is_domain = 0;
		int is_normalized = 0;
		int is_wirestore = 0;
		size_t length = 0;
		int required = descriptor->length;

		switch (rdata_atom_wireformat_type(rrtype, i)) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
			is_domain = 1;
			is_normalized = 1;
			break;
		case DNSLIB_RDATA_WF_LITERAL_DNAME:
			is_domain = 1;
			is_wirestore = 1;
			break;
		case DNSLIB_RDATA_WF_BYTE:
			length = sizeof(uint8_t);
			break;
		case DNSLIB_RDATA_WF_SHORT:
			length = sizeof(uint16_t);
			break;
		case DNSLIB_RDATA_WF_LONG:
			length = sizeof(uint32_t);
			break;
		case DNSLIB_RDATA_WF_TEXT:
		case DNSLIB_RDATA_WF_BINARYWITHLENGTH:
			/* Length is stored in the first byte.  */
			length = 1;
      if (wireformat <= end) {
      }
/*			if (buffer_position(packet) + length <= end) {
				length += buffer_current(packet)[length - 1];
			}*/
			break;
		case DNSLIB_RDATA_WF_A:
			length = sizeof(in_addr_t);
			break;
		case DNSLIB_RDATA_WF_AAAA:
			length = IP6ADDRLEN;
			break;
		case DNSLIB_RDATA_WF_BINARY:
			/* Remaining RDATA is binary.  */
			length = end - wireformat;
//			length = end - buffer_position(packet);
			break;
		case DNSLIB_RDATA_WF_APL:
			length = (sizeof(uint16_t)    /* address family */
				  + sizeof(uint8_t)   /* prefix */
				  + sizeof(uint8_t)); /* length */
			if (wireformat + length <= end) {
				/* Mask out negation bit.  */
//				length += (wireformat[length - 1]
//TODO					   & APL_LENGTH_MASK);
			assert(0); // not yet implemented
			}
			break;
		case DNSLIB_RDATA_WF_IPSECGATEWAY:
			switch(rdata_atom_data(temp_rdatas[1])[0]) /* gateway type */ {
			default:
			case IPSECKEY_NOGATEWAY:
				length = 0;
				break;
			case IPSECKEY_IP4:
				length = 4; //IP4ADDRLEN; XXX
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
			const dnslib_dname_t *dname;

			if (!required && (wireformat == end)) {
				break;
			}
    		
		char *tmp_dname_str = malloc(sizeof(char) * length); //XXX ???

		memcpy(tmp_dname_str, wireformat, length);

		dname = dnslib_dname_new_from_str(tmp_dname_str, strlen(tmp_dname_str), NULL);
			if(is_wirestore) { //XXX WTH...
/*				temp_rdatas[i].raw_data = (uint16_t *) region_alloc(
                                	region, sizeof(uint16_t) + dname->name_size);
				temp_rdatas[i].data[0] = dname->name_size;
				memcpy(temp_rdatas[i].data+1, dname_name(dname),
					dname->name_size); */
			}
			} else {
			if (wireformat + length > end) {
				if (required) {
					/* Truncated RDATA.  */
					return -1;
				} else {
					break;
				}
			}

/*			temp_rdatas[i].data = (uint16_t *) region_alloc(
				region, sizeof(uint16_t) + length);
			temp_rdatas[i].data[0] = length;
			buffer_read(packet, temp_rdatas[i].data + 1, length);*/
		}
	}

	if (wireformat < end) {
		/* Trailing garbage.  */
//		region_destroy(temp_region);
		return -1;
	}

	*items = *temp_rdatas;
/*	*rdatas = (rdata_atom_type *) region_alloc_init(
		region, temp_rdatas, i * sizeof(rdata_atom_type)); */
	return (ssize_t)i;
}



/* Taken from RFC 2535, section 7.  */
dnslib_lookup_table_t dns_algorithms[] = {
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
dnslib_lookup_table_t dns_certificate_types[] = {
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




/* Some global flags... */
static int vflag = 0;
/* if -v then print progress each 'progress' RRs */
static int progress = 10000;

/* Total errors counter */
static long int totalerrors = 0;
static long int totalrrs = 0;

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];
extern uint16_t nsec_highest_rcode;

/*
 * Allocate SIZE+sizeof(uint16_t) bytes and store SIZE in the first
 * element.  Return a pointer to the allocation.
 */
static uint16_t *
alloc_rdata(size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	*result = size;
	return result;
}

uint16_t *
alloc_rdata_init(const void *data, size_t size)
{
	uint16_t *result = malloc(sizeof(uint16_t) + size);
	*result = size;
	memcpy(result + 1, data, size);
	return result;
}

/*
 * These are parser function for generic zone file stuff.
 */
uint16_t *
zparser_conv_hex(const char *hex, size_t len)
{
	/* convert a hex value to wireformat */
	uint16_t *r = NULL;
	uint8_t *t;
	int i;

	if (len % 2 != 0) {
		fprintf(stderr, "number of hex digits must be a multiple of 2");
	} else if (len > MAX_RDLENGTH * 2) {
		fprintf(stderr, "hex data exceeds maximum rdata length (%d)",
				   MAX_RDLENGTH);
	} else {
		/* the length part */

		r = alloc_rdata(len/2);

		t = (uint8_t *)(r + 1);

		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				if (isxdigit((int)*hex)) {
					*t += hexdigit_to_int(*hex) * i;
				} else {
					fprintf(stderr,
						"illegal hex character '%c'",
						(int) *hex);
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
uint16_t *
zparser_conv_hex_length(const char *hex, size_t len)
{
	uint16_t *r = NULL;
	uint8_t *t;
	int i;
	if (len % 2 != 0) {
		fprintf(stderr, "number of hex digits must be a multiple of 2");
	} else if (len > 255 * 2) {
		fprintf(stderr, "hex data exceeds 255 bytes");
	} else {
		uint8_t *l;

		/* the length part */
		r = alloc_rdata(len/2+1);
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
					fprintf(stderr,
						"illegal hex character '%c'",
						(int) *hex);
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

uint16_t *
zparser_conv_time(const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;

	/* Try to scan the time... */
	if (!strptime(time, "%Y%m%d%H%M%S", &tm)) {
		fprintf(stderr, "date and time is expected");
	} else {
		uint32_t l = htonl(mktime_from_utc(&tm));
		r = alloc_rdata_init(&l, sizeof(l));
	}
	return r;
}

uint16_t *
zparser_conv_services(const char *protostr,
		      char *servicestr)
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
		fprintf(stderr, "unknown protocol '%s'", protostr);
		return NULL;
	}

	for (word = strtok(servicestr, sep); word; word = strtok(NULL, sep)) {
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
				fprintf(stderr, "unknown service '%s' for protocol '%s'",
						   word, protostr);
				continue;
			}
		}

		if (port < 0 || port > 65535) {
			fprintf(stderr, "bad port number %d", port);
		} else {
			set_bit(bitmap, port);
			if (port > max_port)
				max_port = port;
		}
	}

	r = alloc_rdata(sizeof(uint8_t) + max_port / 8 + 1);
	p = (uint8_t *) (r + 1);
	*p = proto->p_proto;
	memcpy(p + 1, bitmap, *r);

	return r;
}

uint16_t *
zparser_conv_serial(const char *serialstr)
{
	printf("CONV SERIAL: %s\n", serialstr);
	uint16_t *r = NULL;
	uint32_t serial;
	const char *t;

	serial = strtoserial(serialstr, &t);
	if (*t != '\0') {
		fprintf(stderr, "serial is expected");
	} else {
		serial = htonl(serial);
		r = alloc_rdata_init(&serial, sizeof(serial));
	}
	return r;
}

uint16_t *
zparser_conv_period(const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */
	uint16_t *r = NULL;
	uint32_t period;
	const char *end;

	/* Allocate required space... */
	period = strtottl(periodstr, &end);
	if (*end != '\0') {
		fprintf(stderr, "time period is expected");
	} else {
		period = htonl(period);
		r = alloc_rdata_init(&period, sizeof(period));
	}
	return r;
}

uint16_t *
zparser_conv_short(const char *text)
{
	uint16_t *r = NULL;
	uint16_t value;
	char *end;

	value = htons((uint16_t) strtol(text, &end, 10));
	if (*end != '\0') {
		fprintf(stderr, "integer value is expected");
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_byte(const char *text)
{
	uint16_t *r = NULL;
	uint8_t value;
	char *end;

	value = (uint8_t) strtol(text, &end, 10);
	if (*end != '\0') {
		fprintf(stderr, "integer value is expected");
	} else {
		r = alloc_rdata_init(&value, sizeof(value));
	}
	return r;
}

uint16_t *
zparser_conv_algorithm(const char *text)
{
	const dnslib_lookup_table_t *alg;
	uint8_t id;

	alg = dnslib_lookup_by_name(dns_algorithms, text);
	if (alg) {
		id = (uint8_t) alg->id;
	} else {
		char *end;
		id = (uint8_t) strtol(text, &end, 10);
		if (*end != '\0') {
			fprintf(stderr, "algorithm is expected");
			return NULL;
		}
	}

	return alloc_rdata_init(&id, sizeof(id));
}

uint16_t *
zparser_conv_certificate_type(const char *text)
{
	/* convert a algoritm string to integer */
	const dnslib_lookup_table_t *type;
	uint16_t id;

	type = dnslib_lookup_by_name(dns_certificate_types, text);
	if (type) {
		id = htons((uint16_t) type->id);
	} else {
		char *end;
		id = htons((uint16_t) strtol(text, &end, 10));
		if (*end != '\0') {
			fprintf(stderr, "certificate type is expected");
			return NULL;
		}
	}

	return alloc_rdata_init(&id, sizeof(id));
}

uint16_t *
zparser_conv_a(const char *text)
{
	in_addr_t address;
	uint16_t *r = NULL;

	if (inet_pton(AF_INET, text, &address) != 1) {
		fprintf(stderr, "invalid IPv4 address '%s'", text);
	} else {
		r = alloc_rdata_init(&address, sizeof(address));
	}
	return r;
}

uint16_t *
zparser_conv_aaaa(const char *text)
{
	uint8_t address[IP6ADDRLEN];
	uint16_t *r = NULL;

	if (inet_pton(AF_INET6, text, address) != 1) {
		fprintf(stderr, "invalid IPv6 address '%s'", text);
	} else {
		r = alloc_rdata_init(address, sizeof(address));
	}
	return r;
}

uint16_t *
zparser_conv_text(const char *text, size_t len)
{
	uint16_t *r = NULL;

	if (len > 255) {
		fprintf(stderr, "text string is longer than 255 characters,"
				   " try splitting it into multiple parts");
	} else {
		uint8_t *p;
		r = alloc_rdata(len + 1);
		p = (uint8_t *) (r + 1);
		*p = len;
		memcpy(p + 1, text, len);
	}
	return r;
}

uint16_t *
zparser_conv_dns_name(const uint8_t* name, size_t len)
{
	uint16_t* r = NULL;
	uint8_t* p = NULL;
	r = alloc_rdata(len);
	p = (uint8_t *) (r + 1);
	memcpy(p, name, len);

	return r;
}

uint16_t *
zparser_conv_b32(const char *b32)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	int i;

	if(strcmp(b32, "-") == 0) {
		return alloc_rdata_init("", 1);
	}
	i = my_b32_pton(b32, buffer+1, B64BUFSIZE-1);
	if (i == -1 || i > 255) {
		fprintf(stderr, "invalid base32 data");
	} else {
		buffer[0] = i; /* store length byte */
		r = alloc_rdata_init(buffer, i+1);
	}
	return r;
}

uint16_t *
zparser_conv_b64(const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	uint16_t *r = NULL;
	int i;

	i = b64_pton(b64, buffer, B64BUFSIZE);
	if (i == -1) {
		fprintf(stderr, "invalid base64 data");
	} else {
		r = alloc_rdata_init(buffer, i);
	}
	return r;
}

uint16_t *
zparser_conv_rrtype(const char *text)
{
	uint16_t *r = NULL;
	uint16_t type = dnslib_rrtype_from_string(text);

	if (type == 0) {
		fprintf(stderr, "unrecognized RR type '%s'", text);
	} else {
		type = htons(type);
		r = alloc_rdata_init(&type, sizeof(type));
	}
	return r;
}

uint16_t *
zparser_conv_nxt(uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t i;
	uint16_t last = 0;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0)
			last = i + 1;
	}

	return alloc_rdata_init(nxtbits, last);
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
uint16_t *
zparser_conv_nsec(uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i,j;
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
	ptr = (uint8_t *) (r + 1);

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
static int
parse_int(const char *str,
	  char **end,
	  int *result,
	  const char *name,
	  int min,
	  int max)
{
	*result = (int) strtol(str, end, 10);
	if (*result < min || *result > max) {
		fprintf(stderr, "%s must be within the range [%d .. %d]",
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
				1000000,10000000,100000000,1000000000};

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t
precsize_aton (char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit((int)*cp))
		mval = mval * 10 + hexdigit_to_int(*cp++);

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit((int)*cp)) {
			cmval = hexdigit_to_int(*cp++) * 10;
			if (isdigit((int)*cp)) {
				cmval += hexdigit_to_int(*cp++);
			}
		}
	}

	if(mval >= poweroften[7]) {
		/* integer overflow possible for *100 */
		mantissa = mval / poweroften[7];
		exponent = 9; /* max */
	}
	else {
		cmval = (mval * 100) + cmval;

		for (exponent = 0; exponent < 9; exponent++)
			if (cmval < poweroften[exponent+1])
				break;

		mantissa = cmval / poweroften[exponent];
	}
	if (mantissa > 9)
		mantissa = 9;

	retval = (mantissa << 4) | exponent;

	if (*cp == 'm') cp++;

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
uint16_t *
zparser_conv_loc(char *str)
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

	for(;;) {
		deg = min = secs = 0;

		/* Degrees */
		if (*str == '\0') {
			fprintf(stderr, "unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180))
			return NULL;
		if (!isspace((int)*str)) {
			fprintf(stderr, "space expected after degrees");
			return NULL;
		}
		++str;

		/* Minutes? */
		if (isdigit((int)*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60))
				return NULL;
			if (!isspace((int)*str)) {
				fprintf(stderr, "space expected after minutes");
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

			if (*str == '.' && !parse_int(str + 1, &str, &i, "seconds fraction", 0, 999)) {
				return NULL;
			}

			if (!isspace((int)*str)) {
				fprintf(stderr, "space expected after seconds");
				return NULL;
			}

			if (sscanf(start, "%lf", &d) != 1) {
				fprintf(stderr, "error parsing seconds");
			}

			if (d < 0.0 || d > 60.0) {
				fprintf(stderr, "seconds not in range 0.0 .. 60.0");
			}

			secs = (int) (d * 1000.0 + 0.5);
			++str;
		}

		switch(*str) {
		case 'N':
		case 'n':
			lat = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'E':
		case 'e':
			lon = ((uint32_t)1<<31) + (deg * 3600000 + min * 60000 + secs);
			break;
		case 'S':
		case 's':
			lat = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		case 'W':
		case 'w':
			lon = ((uint32_t)1<<31) - (deg * 3600000 + min * 60000 + secs);
			break;
		default:
			fprintf(stderr, "invalid latitude/longtitude: '%c'", *str);
			return NULL;
		}
		++str;

		if (lat != 0 && lon != 0)
			break;

		if (!isspace((int)*str)) {
			fprintf(stderr, "space expected after latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		fprintf(stderr, "unexpected end of LOC data");
		return NULL;
	}

	if (!isspace((int)*str)) {
		fprintf(stderr, "space expected before altitude");
		return NULL;
	}
	++str;

	start = str;

	/* Sign */
	if (*str == '+' || *str == '-') {
		++str;
	}

	/* Meters of altitude... */
	(void) strtol(str, &str, 10);
	switch(*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		if (!parse_int(str + 1, &str, &i, "altitude fraction", 0, 99)) {
			return NULL;
		}
		if (!isspace((int)*str) && *str != '\0' && *str != 'm') {
			fprintf(stderr, "altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		fprintf(stderr, "altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace((int)*str) && *str != '\0')
		++str;

	if (sscanf(start, "%lf", &d) != 1) {
		fprintf(stderr, "error parsing altitude");
	}

	alt = (uint32_t) (10000000.0 + d * 100 + 0.5);

	if (!isspace((int)*str) && *str != '\0') {
		fprintf(stderr, "unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for(i = 1; isspace((int)*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace((int)*str) && *str != '\0') {
			fprintf(stderr, "invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = alloc_rdata(16);
	p = (uint32_t *) (r + 1);

	memmove(p, vszhpvp, 4);
	write_uint32(p + 1, lat);
	write_uint32(p + 2, lon);
	write_uint32(p + 3, alt);

	return r;
}

/*
 * Convert an APL RR RDATA element.
 */
uint16_t *
zparser_conv_apl_rdata(char *str)
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
		fprintf(stderr, "address family separator is missing");
		return NULL;
	}
	if (!slash) {
		fprintf(stderr, "prefix separator is missing");
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
		fprintf(stderr, "invalid address family '%s'", str);
		return NULL;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		fprintf(stderr, "invalid address '%s'", colon + 1);
		return NULL;
	} else if (rc == -1) {
		fprintf(stderr, "inet_pton failed: %s", strerror(errno));
		return NULL;
	}

	/* Strip trailing zero octets.	*/
	while (length > 0 && address[length - 1] == 0)
		--length;


	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		fprintf(stderr, "prefix not in the range 0 .. %d", maximum_prefix);
		return NULL;
	} else if (*end != '\0') {
		fprintf(stderr, "invalid prefix '%s'", slash + 1);
		return NULL;
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	r = alloc_rdata(rdlength);
	t = (uint8_t *) (r + 1);

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

uint32_t
zparser_ttl2int(const char *ttlstr, int* error)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	uint32_t ttl;
	const char *t;

	ttl = strtottl(ttlstr, &t);
	if (*t != 0) {
		fprintf(stderr, "invalid TTL value: %s",ttlstr);
		*error = 1;
	}

	return ttl;
}


//RDATAADD

void
zadd_rdata_wireformat(uint16_t *data)
{
	printf("RDATA: WIRE %s\n", data);
/*	if (parser->current_rrset.rdata_count >= MAXRDATALEN) {
		fprintf(stderr, "too many rdata elements");
	} else {*/

	printf("setting index %d\n", parser->rdata_count);
	dnslib_rdata_item_t *item = malloc(sizeof(dnslib_rdata_item_t));
	item->raw_data = (uint8_t*)data;
	parser->temporary_items[parser->rdata_count] = *item;
	parser->rdata_count++;
}

/**
 * Used for TXT RR's to grow with undefined number of strings.
 */
void
zadd_rdata_txt_wireformat(uint16_t *data, int first)
{
	printf("RDATA: TXT WIRE\n");
	dnslib_rdata_item_t *rd;

	/* First STR in str_seq, allocate 65K in first unused rdata
	 * else find last used rdata */
	if (first) {
		rd = &parser->temporary_items[parser->rdata_count];
//		if ((rd->data = (uint16_t *) region_alloc(parser->rr_region,
//			sizeof(uint16_t) + 65535 * sizeof(uint8_t))) == NULL) {
//			fprintf(stderr, "Could not allocate memory for TXT RR");
//			return;
//		}
		parser->rdata_count++;
		rd->raw_data[0] = 0;
	}
	else {
		rd = &parser->temporary_items[parser->rdata_count-1];
  }

	if ((size_t)rd->raw_data[0] + (size_t)data[0] > 65535) {
		fprintf(stderr, "too large rdata element");
		return;
	}
  //XXX why + 2? maybe there are two lengts
	memcpy((uint8_t *)rd->raw_data + 2 + rd->raw_data[0], data + 1, data[0]);
	rd->raw_data[0] += data[0];
}

/**
 * Clean up after last call of zadd_rdata_txt_wireformat
 */
void
zadd_rdata_txt_clean_wireformat()
{
//	uint16_t *tmp_data;
//	rdata_atom_type *rd = &parser->current_rr.rdatas[parser->current_rr.rdata_count-1];
//	if ((tmp_data = (uint16_t *) region_alloc(parser->region,
//		rd->data[0] + 2)) != NULL) {
//		memcpy(tmp_data, rd->data, rd->data[0] + 2);
//		rd->data = tmp_data;
//	}
//	else {
//		/* We could not get memory in non-volatile region */
//		fprintf(stderr, "could not allocate memory for rdata");
//		return;
//	}
}

void
zadd_rdata_domain(dnslib_dname_t *dname)
{
	printf("RDATA: DOMAIN %s\n", dnslib_dname_to_str(dname));
//	if (parser->current_rrset.rdata_count >= MAXRDATALEN) {
//		fprintf(stderr, "too many rdata elements");
//	} else {

	dnslib_rdata_item_t *item = malloc(sizeof(dnslib_rdata_item_t));
	item->dname = dname;
	printf("setting index %d\n", parser->rdata_count);
	parser->temporary_items[parser->rdata_count] = *item;
	parser->rdata_count++;
//		parser->current_rr.rdatas[parser->current_rr.rdata_count].domain
//			= domain;
//		++parser->current_rr.rdata_count;
//	}
}

void
parse_unknown_rdata(uint16_t type, uint16_t *wireformat)
{
	printf("RDATA: UNKNOWN DATA\n");
//	buffer_type packet;
	uint16_t size;
	ssize_t rdata_count;
	ssize_t i;
	dnslib_rdata_item_t *items;

	if (wireformat) {
		size = *wireformat;
	} else {
		return;
	}

//	buffer_create_from(&packet, wireformat + 1, *wireformat);
	rdata_count = rdata_wireformat_to_rdata_atoms(wireformat, type, size, items);
	if (rdata_count == -1) {
		fprintf(stderr, "bad unknown RDATA");
		return;
	}

	for (i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			zadd_rdata_domain(items[i].dname);
		} else {
        //XXX won't this create size two times?
			zadd_rdata_wireformat(items[i].raw_data);
		}
	}
}


/*
 * Compares two rdata arrays.
 *
 * Returns:
 *
 *	zero if they are equal
 *	non-zero if not
 *
 */

// XXX we have dnslib_rdata_compare, but it is not working yet

//static int
//zrdatacmp(uint16_t type, rr_type *a, rr_type *b)
//{
//	int i = 0;
//
//	assert(a);
//	assert(b);
//
//	/* One is shorter than another */
//	if (a->rdata_count != b->rdata_count)
//		return 1;
//
//	/* Compare element by element */
//	for (i = 0; i < a->rdata_count; ++i) {
//		if (rdata_atom_is_domain(type, i)) {
//			if (rdata_atom_domain(a->rdatas[i])
//			    != rdata_atom_domain(b->rdatas[i]))
//			{
//				return 1;
//			}
//		} else {
//			if (rdata_atom_size(a->rdatas[i])
//			    != rdata_atom_size(b->rdatas[i]))
//			{
//				return 1;
//			}
//			if (memcmp(rdata_atom_data(a->rdatas[i]),
//				   rdata_atom_data(b->rdatas[i]),
//				   rdata_atom_size(a->rdatas[i])) != 0)
//			{
//				return 1;
//			}
//		}
//	}
//
//	/* Otherwise they are equal */
//	return 0;
//}

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
static int
zone_open(const char *filename, uint32_t ttl, uint16_t rclass,
	  const dnslib_node_t *origin)
{
	/* Open the zone file... */
	if (strcmp(filename, "-") == 0) {
		yyin = stdin;
		filename = "<stdin>";
	} else if (!(yyin = fopen(filename, "r"))) {
		return 0;
	}

//	/* Open the network database */
//	setprotoent(1);
//	setservent(1);
//
	zparser_init(filename, ttl, rclass, origin);
//
	return 1;
}


void
set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
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

int
process_rr(void)
{
	printf("PROCESS RR CALLED\n");
	dnslib_zone_t *zone = parser->current_zone;
	dnslib_rrset_t *current_rrset = &parser->current_rrset;
	printf("\n%s\n", dnslib_dname_to_str(current_rrset->owner));
	dnslib_rrset_t *rrset;
	size_t max_rdlength;
	int i;
	dnslib_rrtype_descriptor_t *descriptor
		= dnslib_rrtype_descriptor_by_type(current_rrset->type);


	assert(parser->current_rrset.rdata->count == descriptor->length);

	/* We only support IN class */
/*	if (current_rrset->rclass != DNSLIB_CLASS_IN) {
		fprintf(stderr, "only class IN is supported");
		return 0;
	}*/

	/* Make sure the maximum RDLENGTH does not exceed 65535 bytes.	*/
//	max_rdlength = rdata_maximum_wireformat_size(
//		descriptor, rr->rdata_count, rr->rdatas);

//	if (max_rdlength > MAX_RDLENGTH) {
//		fprintf(stderr, "maximum rdata length exceeds %d octets", MAX_RDLENGTH);
//		return 0;
//	}


	/* Do we have the zone already? */
	if (!zone)
	{
		//our apex should also be SOA
		assert(current_rrset->type == DNSLIB_RRTYPE_SOA);
		//soa comes first, therefore, there should not be any node assigned to
		//its owner.
		
		dnslib_node_t *soa_node;

		assert(parser->origin != NULL);

		//this should AFAIK always be root

		zone = dnslib_zone_new(parser->default_apex);

		soa_node = dnslib_node_new(current_rrset->owner, parser->origin);

		dnslib_zone_add_node(zone, soa_node);

		parser->current_zone = zone;

		printf("ZONE CREATED\n");
	}

	if (current_rrset->type == DNSLIB_RRTYPE_RRSIG) {
		uint16_t tmp_type = current_rrset->rdata->items[0].raw_data[3];
		dnslib_rrsig_set_t *rrsig =
			dnslib_rrsig_set_new(current_rrset->owner,
			                     tmp_type,
					     current_rrset->rclass,
					     current_rrset->ttl);

		assert(current_rrset->rdata->next == NULL);

		rrsig->rdata = current_rrset->rdata;

			//TODO if rrset exists and it has already assigned rrsig to it, merge
		dnslib_node_t *tmp_node = dnslib_zone_find_node(zone,
		                                                rrsig->owner);
		assert(tmp_node != NULL);

		printf("searching for type: %d\n", current_rrset->rdata->items[0].raw_data[3]);

		//TODO check
		dnslib_rrset_t *tmp_rrset =
			dnslib_node_get_rrset(tmp_node, rrsig->type);

		printf("%s\n", dnslib_dname_to_str(rrsig->owner));

		assert(tmp_rrset != NULL);

		//TODO check

		tmp_rrset->rrsigs = rrsig;

		return;

	}

/*	if (!dname_is_subdomain(domain_dname(rr->owner),
	XXX			domain_dname(zone->apex)))
	{
		fprintf(stderr, "out of zone data");
		return 0;
	}*/ //this does not have to be here for the time being

	dnslib_node_t *node;
	node = dnslib_zone_find_node(zone, current_rrset->owner);
	if (node == NULL) {

		dnslib_node_t *tmp_node;
		dnslib_node_t *last_node = dnslib_node_new(current_rrset->owner, NULL);
		node = last_node;
		dnslib_dname_t *tmp_owner = current_rrset->owner;
		dnslib_dname_t *chopped = dnslib_dname_left_chop(current_rrset->owner);

		while ((tmp_node = dnslib_zone_find_node(zone, chopped)) == NULL) {
			tmp_node = dnslib_node_new(tmp_owner, NULL);
			last_node->parent = tmp_node;
			dnslib_zone_add_node(zone, tmp_node);
			last_node = tmp_node;
			chopped = dnslib_dname_left_chop(tmp_owner);
			tmp_owner = chopped;
		}

		last_node->parent = tmp_node;

		assert(tmp_node != NULL);

		printf("NODE CREATED\n");
	}
	rrset = dnslib_node_get_rrset(node, current_rrset->type);
	if (!rrset) {
		rrset = dnslib_rrset_new(current_rrset->owner, current_rrset->type,
				current_rrset->rclass, current_rrset->ttl);
		printf("RRSET CREATED\n");

		dnslib_rrset_add_rdata(rrset, current_rrset->rdata);
		//TODO check return value

		printf("RDATA ADDED\n");

		/* Add it */
		dnslib_node_add_rrset(node, rrset);

		printf("RRSET ADDED\n");
	} else {
		if (current_rrset->type !=
			DNSLIB_RRTYPE_RRSIG && rrset->ttl !=
			current_rrset->ttl) {
			fprintf(stderr,
				"TTL does not match the TTL of the RRset");
		}

		dnslib_rrset_add_rdata(rrset, current_rrset->rdata);

//		/* Search for possible duplicates... */
//		for (i = 0; i < rrset->rr_count; i++) {
//			if (!zrdatacmp(rr->type, rr, &rrset->rrs[i])) {
//				break;
//			}
//		}
//
//		/* Discard the duplicates... */
//		if (i < rrset->rr_count) {
//			return 0;
//		}

		/* Add it... */
//		rrset->rrs = (rr_type *) xrealloc(
//			rrset->rrs,
//			(rrset->rr_count + 1) * sizeof(rr_type));
//		rrset->rrs[rrset->rr_count] = *rr;
//		++rrset->rr_count;



		// TODO create item, add it to the rrset
	}

//	if(current_rrset->type == TYPE_DNAME && rrset->rr_count > 1) {
//		fprintf(stderr, "multiple DNAMEs at the same name");
//	}
//	if(current_rrset->type == TYPE_CNAME && rrset->rr_count > 1) {
//		fprintf(stderr, "multiple CNAMEs at the same name");
//	}
//	if((rr->type == TYPE_DNAME && domain_find_rrset(rr->owner, zone, TYPE_CNAME))
//	 ||(rr->type == TYPE_CNAME && domain_find_rrset(rr->owner, zone, TYPE_DNAME))) {
//		fprintf(stderr, "DNAME and CNAME at the same name");
//	}
//	if(domain_find_rrset(rr->owner, zone, TYPE_CNAME) &&
//		domain_find_non_cname_rrset(rr->owner, zone)) {
//		fprintf(stderr, "CNAME and other data at the same name");
//	}
//
//	if (rr->type == TYPE_RRSIG && rr_rrsig_type_covered(rr) == TYPE_SOA) {
//		rrset->zone->is_secure = 1;
//	}

	/* Check we have SOA */
//	if (zone->soa_rrset == NULL) {
//		if (rr->type == TYPE_SOA) {
//			if (rr->owner != zone->apex) {
//				fprintf(stderr,
//					"SOA record with invalid domain name");
//			} else {
//				zone->soa_rrset = rrset;
//			}
//		}
//	}
//	else if (rr->type == TYPE_SOA) {
//		fprintf(stderr, "duplicate SOA record discarded");
//		--rrset->rr_count;
//	}
//
//	/* Is this a zone NS? */
//	if (rr->type == TYPE_NS && rr->owner == zone->apex) {
//		zone->ns_rrset = rrset;
//	}
	if (vflag > 1 && totalrrs > 0 && (totalrrs % progress == 0)) {
		fprintf(stdout, "%ld\n", totalrrs);
	}
	dnslib_zone_dump(zone);
	++totalrrs;
	return 1;
}

/*
 * Find rrset type for any zone
 */
//static rrset_type*
//domain_find_rrset_any(domain_type *domain, uint16_t type)
//{
//	rrset_type *result = domain->rrsets;
//	while (result) {
//		if (rrset_rrtype(result) == type) {
//			return result;
//		}
//		result = result->next;
//	}
//	return NULL;
//}

/*
 * Check for DNAME type. Nothing is allowed below it
 */
//static void
//check_dname(namedb_type* db)
//{
//	domain_type* domain;
//	RBTREE_FOR(domain, domain_type*, db->domains->names_to_domains)
//	{
//		if(domain->is_existing) {
//			/* there may not be DNAMEs above it */
//			domain_type* parent = domain->parent;
//#ifdef NSEC3
//			if(domain_has_only_NSEC3(domain, NULL))
//				continue;
//#endif
//			while(parent) {
//				if(domain_find_rrset_any(parent, TYPE_DNAME)) {
//					fprintf(stderr, "While checking node %s,",
//						dname_to_string(domain_dname(domain), NULL));
//					fprintf(stderr, "DNAME at %s has data below it. "
//						"This is not allowed (rfc 2672).",
//						dname_to_string(domain_dname(parent), NULL));
//					exit(1);
//				}
//				parent = parent->parent;
//			}
//		}
//	}
//}

/*
 * Reads the specified zone into the memory
 * nsd_options can be NULL if no config file is passed.
 *
 */
void
zone_read(const char *name, const char *zonefile) //, nsd_options_t* nsd_options)
{
	const dnslib_dname_t *dname;

//	dname = dname_parse(parser->region, name);
	name = "example.com.";
	
	dname = dnslib_dname_new_from_str(name, strlen(name), NULL);

	//XXX not sure about this workaround

	dnslib_node_t *origin_node;

	origin_node = dnslib_node_new(dname, NULL);
	
	printf("APEX NODE CREATED WITH POINTER: %p\n", origin_node); 

	assert(origin_node->next == NULL);

	if (!dname) {
		fprintf(stderr, "incorrect zone name '%s'", name);
		return;
	}

//#ifndef ROOT_SERVER
//	/* Is it a root zone? Are we a root server then? Idiot proof. */
//	if (dname->label_count == 1) {
//		fprintf(stderr, "not configured as a root server");
//		return;
//	}
//#endif
//
	/* Open the zone file */
	if (!zone_open(zonefile, 3600, DNSLIB_CLASS_IN, origin_node)) {
//		if(nsd_options) {
//			/* check for secondary zone, they can start with no zone info */
//			zone_options_t* zopt = zone_options_find(nsd_options, dname);
//			if(zopt && zone_is_slave(zopt)) {
//				zc_warning("slave zone %s with no zonefile '%s'(%s) will "
//					"force zone transfer.",
//					name, zonefile, strerror(errno));
//				return;
//			}
//		}
//		/* cannot happen with stdin - so no fix needed for zonefile */
		fprintf(stderr, "cannot open '%s': %s", zonefile, strerror(errno));
		return;
	}
//
//	/* Parse and process all RRs.  */
	yyparse();
//
//	/* check if zone file contained a correct SOA record */
//	if (parser->current_zone && parser->current_zone->soa_rrset
//		&& parser->current_zone->soa_rrset->rr_count!=0)
//	{
//		if(dname_compare(domain_dname(
//			parser->current_zone->soa_rrset->rrs[0].owner),
//			dname) != 0) {
//			fprintf(stderr, "zone configured as '%s', but SOA has owner '%s'.",
//				name, dname_to_string(
//				domain_dname(parser->current_zone->
//				soa_rrset->rrs[0].owner), NULL));
//		}
//	}
//
	fclose(yyin);
//
//	fflush(stdout);
	totalerrors += parser->errors;
//	parser->filename = NULL;
}

