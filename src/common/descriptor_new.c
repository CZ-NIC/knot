#include "common/descriptor_new.h"

/*! \brief RR type descriptors. */
static knot_descriptor_t
       knot_descriptors[] = {
        { 0, { KNOT_RDATA_WF_REMAINDER }},
        /* 1 */
  	{ KNOT_RRTYPE_A, { 4 }},
  	/* 2 */
  	{ KNOT_RRTYPE_NS, { KNOT_RDATA_WF_COMPRESSED_DNAME }},
  	/* 3 */
  	{ KNOT_RRTYPE_CNAME, { KNOT_RDATA_WF_COMPRESSED_DNAME }},
  	/* 6 */
  	[6] = { KNOT_RRTYPE_SOA,
	  { KNOT_RDATA_WF_COMPRESSED_DNAME, KNOT_RDATA_WF_COMPRESSED_DNAME,
	    20 }},
  	/* 7 */
  	{ KNOT_RRTYPE_PTR, { KNOT_RDATA_WF_COMPRESSED_DNAME }},
  	/* 13 */
  	[13] = { KNOT_RRTYPE_HINFO, { KNOT_RDATA_WF_REMAINDER }},
  	/* 14 */
  	{ KNOT_RRTYPE_MINFO, { KNOT_RDATA_WF_COMPRESSED_DNAME,
	    KNOT_RDATA_WF_COMPRESSED_DNAME }},
  	/* 15 */
  	{ KNOT_RRTYPE_MX, { 2, KNOT_RDATA_WF_COMPRESSED_DNAME }},
  	/* 16 */
	{ KNOT_RRTYPE_TXT,{ KNOT_RDATA_WF_REMAINDER }},
  	/* 17 */
  	{ KNOT_RRTYPE_RP, { KNOT_RDATA_WF_COMPRESSED_DNAME,
	    KNOT_RDATA_WF_COMPRESSED_DNAME }},
  	/* 18 */
  	{ KNOT_RRTYPE_AFSDB, { 2, KNOT_RDATA_WF_COMPRESSED_DNAME }},
  	/* 19 */
  	{ KNOT_RRTYPE_AAAA, { 16 }},
  	/* 29 */
        [29] = { KNOT_RRTYPE_LOC, { KNOT_RDATA_WF_REMAINDER }},
        [33] = { KNOT_RRTYPE_SRV, { 6, KNOT_RDATA_WF_UNCOMPRESSED_DNAME }},
  	[35] = { KNOT_RRTYPE_NAPTR, { KNOT_RDATA_WF_NAPTR_HEADER,
            KNOT_RDATA_WF_UNCOMPRESSED_DNAME }},
  	/* 37 */
  	[37] = { KNOT_RRTYPE_CERT,
  	  { 5, KNOT_RDATA_WF_REMAINDER }},
  	/* 38 */
  	{ KNOT_RRTYPE_DNAME, { KNOT_RDATA_WF_UNCOMPRESSED_DNAME }},
  	/* 40 */
  	[40] = { KNOT_RRTYPE_OPT, { KNOT_RDATA_WF_REMAINDER }},
  	/* 42 */
	[42] = { KNOT_RRTYPE_APL, { KNOT_RDATA_WF_REMAINDER }},
  	/* 43 */
  	{ KNOT_RRTYPE_DS,
  	  { 4, KNOT_RDATA_WF_REMAINDER }},
  	/* 44 */
  	{ KNOT_RRTYPE_SSHFP,{ 2,
	    KNOT_RDATA_WF_REMAINDER }},
  	/* 45 */
  	{ KNOT_RRTYPE_IPSECKEY,
  	  { 2, KNOT_RDATA_WF_REMAINDER }},
  	/* 46 */
  	{ KNOT_RRTYPE_RRSIG, { 20, KNOT_RDATA_WF_LITERAL_DNAME,
	    KNOT_RDATA_WF_REMAINDER }},
  	/* 47 */
  	{ KNOT_RRTYPE_NSEC, 
	  { KNOT_RDATA_WF_LITERAL_DNAME, KNOT_RDATA_WF_REMAINDER }},
  	/* 48 */
  	{ KNOT_RRTYPE_DNSKEY, { 4, KNOT_RDATA_WF_REMAINDER }},
  	/* 49 */
  	{ KNOT_RRTYPE_DHCID, { KNOT_RDATA_WF_REMAINDER }},
  	/* 50 */
  	{ KNOT_RRTYPE_NSEC3, { 4, KNOT_RDATA_WF_REMAINDER }},
  	/* 51 */
  	{ KNOT_RRTYPE_NSEC3PARAM, { 4, KNOT_RDATA_WF_REMAINDER }},
  	/* 52 */
  	{ KNOT_RRTYPE_TLSA, { 3, KNOT_RDATA_WF_REMAINDER }},
  	/* 99 */
	[99] = { KNOT_RRTYPE_SPF, 
  	  { KNOT_RDATA_WF_REMAINDER }},
        /* TSIG pseudo RR. */
        [250] = { KNOT_RRTYPE_TSIG,
		 { KNOT_RDATA_WF_UNCOMPRESSED_DNAME, KNOT_RDATA_WF_REMAINDER }}
};

knot_descriptor_t *knot_descriptor_by_type(uint16_t type)
{
	if (type <= KNOT_RRTYPE_TSIG) {
		return &knot_descriptors[type];
	} else {
		return &knot_descriptors[0];
	}
}

int knot_rrtype_is_metatype(uint16_t type)
{
	return (type == KNOT_RRTYPE_ANY
	        || type == KNOT_RRTYPE_AXFR
	        || type == KNOT_RRTYPE_IXFR
	        || type == KNOT_RRTYPE_OPT);
}


