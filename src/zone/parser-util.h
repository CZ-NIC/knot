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

#include "zonec.h"
#include "descriptor.h"

size_t strlcpy(char *dst, const char *src, size_t siz);
int inet_pton4(src, dst);
int inet_pton6(src, dst);
const char * inet_ntop(int af, const void *src, char *dst, size_t size);
const char * inet_ntop4(const u_char *src, char *dst, size_t size);
const char * inet_ntop6(const u_char *src, char *dst, size_t size);
static int my_b32_pton(const char *src, uint8_t *target, size_t tsize);
int inet_pton(af, src, dst);
void b64_initialize_rmap();
int b64_pton_do(char const *src, uint8_t *target, size_t targsize);
int b64_pton_len(char const *src);
int b64_pton(char const *src, uint8_t *target, size_t targsize);
void set_bit(uint8_t bits[], size_t index);
uint32_t strtoserial(const char* nptr, const char** endptr);
void write_uint32(void *dst, uint32_t data);
uint32_t strtottl(const char *nptr, const char **endptr);

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
