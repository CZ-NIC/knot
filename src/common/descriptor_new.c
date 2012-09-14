#include "common/descriptor_new.h"

/*!
 * \brief RR type descriptors.
 */
static const knot_descriptor_t knot_descriptors[] = {
    [KNOT_RRTYPE_A]          = { 4 },
    [KNOT_RRTYPE_NS]         = { KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_CNAME]      = { KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_SOA]        = { KNOT_RDATA_WF_COMPRESSED_DNAME,
                                 KNOT_RDATA_WF_COMPRESSED_DNAME,
                                 20 },
    [KNOT_RRTYPE_PTR]        = { KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_HINFO]      = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_MINFO]      = { KNOT_RDATA_WF_COMPRESSED_DNAME,
                                 KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_MX]         = { 2, KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_TXT]        = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_RP]         = { KNOT_RDATA_WF_COMPRESSED_DNAME,
                                 KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_AFSDB]      = { 2, KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_RT]         = { 2, KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_KEY]        = { 4, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_AAAA]       = { 16 },
    [KNOT_RRTYPE_LOC]        = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_SRV]        = { 6, KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
    [KNOT_RRTYPE_NAPTR]      = { KNOT_RDATA_WF_NAPTR_HEADER,
                                 KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
    [KNOT_RRTYPE_KX]         = { 2, KNOT_RDATA_WF_COMPRESSED_DNAME },
    [KNOT_RRTYPE_CERT]       = { 5, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_DNAME]      = { KNOT_RDATA_WF_UNCOMPRESSED_DNAME },
    [KNOT_RRTYPE_OPT]        = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_APL]        = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_DS]         = { 4, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_SSHFP]      = { 2, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_IPSECKEY]   = { 2, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_RRSIG]      = { 20, KNOT_RDATA_WF_LITERAL_DNAME,
                                 KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_NSEC]       = { KNOT_RDATA_WF_LITERAL_DNAME,
                                 KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_DNSKEY]     = { 4, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_DHCID]      = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_NSEC3]      = { 4, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_NSEC3PARAM] = { 4, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_TLSA]       = { 3, KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_SPF]        = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_TKEY]       = { KNOT_RDATA_WF_REMAINDER },
    [KNOT_RRTYPE_TSIG]       = { KNOT_RDATA_WF_UNCOMPRESSED_DNAME,
                                 KNOT_RDATA_WF_REMAINDER },
};

const knot_descriptor_t *knot_descriptor_by_type(const uint16_t type)
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


