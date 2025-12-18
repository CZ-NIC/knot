/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "libknot/attribute.h"
#include "libknot/codes.h"
#include "libknot/consts.h"
#include "libknot/rrtype/opt.h"
#include "libknot/dnssec/key.h"

_public_
const knot_lookup_t knot_opcode_names[] = {
	{ KNOT_OPCODE_QUERY,  "QUERY" },
	{ KNOT_OPCODE_IQUERY, "IQUERY" },
	{ KNOT_OPCODE_STATUS, "STATUS" },
	{ KNOT_OPCODE_NOTIFY, "NOTIFY" },
	{ KNOT_OPCODE_UPDATE, "UPDATE" },
	{ 0, NULL }
};

_public_
const knot_lookup_t knot_rcode_names[] = {
	{ KNOT_RCODE_NOERROR,   "NOERROR" },
	{ KNOT_RCODE_FORMERR,   "FORMERR" },
	{ KNOT_RCODE_SERVFAIL,  "SERVFAIL" },
	{ KNOT_RCODE_NXDOMAIN,  "NXDOMAIN" },
	{ KNOT_RCODE_NOTIMPL,   "NOTIMPL" },
	{ KNOT_RCODE_REFUSED,   "REFUSED" },
	{ KNOT_RCODE_YXDOMAIN,  "YXDOMAIN" },
	{ KNOT_RCODE_YXRRSET,   "YXRRSET" },
	{ KNOT_RCODE_NXRRSET,   "NXRRSET" },
	{ KNOT_RCODE_NOTAUTH,   "NOTAUTH" },
	{ KNOT_RCODE_NOTZONE,   "NOTZONE" },
	{ KNOT_RCODE_BADVERS,   "BADVERS" },
	{ KNOT_RCODE_BADKEY,    "BADKEY" },
	{ KNOT_RCODE_BADTIME,   "BADTIME" },
	{ KNOT_RCODE_BADMODE,   "BADMODE" },
	{ KNOT_RCODE_BADNAME,   "BADNAME" },
	{ KNOT_RCODE_BADALG,    "BADALG" },
	{ KNOT_RCODE_BADTRUNC,  "BADTRUNC" },
	{ KNOT_RCODE_BADCOOKIE, "BADCOOKIE" },
	{ 0, NULL }
};

_public_
const knot_lookup_t knot_tsig_rcode_names[] = {
	{ KNOT_RCODE_BADSIG, "BADSIG" },
	{ 0, NULL }
};

_public_
const knot_lookup_t knot_edns_ede_names[] = {
	{ KNOT_EDNS_EDE_OTHER,            "Other" },
	{ KNOT_EDNS_EDE_DNSKEY_ALG,       "Unsupported DNSKEY Algorithm" },
	{ KNOT_EDNS_EDE_DS_DIGEST,        "Unsupported DS Digest Type" },
	{ KNOT_EDNS_EDE_STALE,            "Stale Answer" },
	{ KNOT_EDNS_EDE_FORGED,           "Forged Answer" },
	{ KNOT_EDNS_EDE_INDETERMINATE,    "DNSSEC Indeterminate" },
	{ KNOT_EDNS_EDE_BOGUS,            "DNSSEC Bogus" },
	{ KNOT_EDNS_EDE_SIG_EXPIRED,      "Signature Expired" },
	{ KNOT_EDNS_EDE_SIG_NOTYET,       "Signature Not Yet Valid" },
	{ KNOT_EDNS_EDE_DNSKEY_MISS,      "DNSKEY Missing" },
	{ KNOT_EDNS_EDE_RRSIG_MISS,       "RRSIGs Missing" },
	{ KNOT_EDNS_EDE_DNSKEY_BIT,       "No Zone Key Bit Set" },
	{ KNOT_EDNS_EDE_NSEC_MISS,        "NSEC Missing" },
	{ KNOT_EDNS_EDE_CACHED_ERR,       "Cached Error" },
	{ KNOT_EDNS_EDE_NOT_READY,        "Not Ready" },
	{ KNOT_EDNS_EDE_BLOCKED,          "Blocked" },
	{ KNOT_EDNS_EDE_CENSORED,         "Censored" },
	{ KNOT_EDNS_EDE_FILTERED,         "Filtered" },
	{ KNOT_EDNS_EDE_PROHIBITED,       "Prohibited" },
	{ KNOT_EDNS_EDE_STALE_NXD,        "Stale NXDOMAIN Answer" },
	{ KNOT_EDNS_EDE_NOTAUTH,          "Not Authoritative" },
	{ KNOT_EDNS_EDE_NOTSUP,           "Not Supported" },
	{ KNOT_EDNS_EDE_NREACH_AUTH,      "No Reachable Authority" },
	{ KNOT_EDNS_EDE_NETWORK,          "Network Error" },
	{ KNOT_EDNS_EDE_INV_DATA,         "Invalid Data" },
	{ KNOT_EDNS_EDE_EXPIRED_INV,      "Signature Expired before Valid" },
	{ KNOT_EDNS_EDE_TOO_EARLY,        "Too Early" },
	{ KNOT_EDNS_EDE_NSEC3_ITERS,      "Unsupported NSEC3 Iterations Value" },
	{ KNOT_EDNS_EDE_NONCONF_POLICY,   "Unable to conform to policy" },
	{ KNOT_EDNS_EDE_SYNTHESIZED,      "Synthesized" },
	{ KNOT_EDNS_EDE_INV_QTYPE,        "Invalid Query Type" },
	{ 0, NULL }
};

_public_
const knot_lookup_t knot_dnssec_alg_names[] = {
	{ DNSSEC_KEY_ALGORITHM_DELETE,            "DELETE" },
	{ DNSSEC_KEY_ALGORITHM_RSA_MD5,           "RSAMD5" },
	{ DNSSEC_KEY_ALGORITHM_DH,                "DH" },
	{ DNSSEC_KEY_ALGORITHM_DSA,               "DSA" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1,          "RSASHA1" },
	{ DNSSEC_KEY_ALGORITHM_DSA_NSEC3_SHA1,    "DSA_NSEC3_SHA1" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3,    "RSASHA1_NSEC3_SHA1" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA256,        "RSASHA256" },
	{ DNSSEC_KEY_ALGORITHM_RSA_SHA512,        "RSASHA512" },
	{ DNSSEC_KEY_ALGORITHM_ECC_GOST,          "ECC_GOST" },
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256, "ECDSAP256SHA256" },
	{ DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, "ECDSAP384SHA384" },
	{ DNSSEC_KEY_ALGORITHM_ED25519,           "ED25519" },
	{ DNSSEC_KEY_ALGORITHM_ED448,             "ED448" },
	{ DNSSEC_KEY_ALGORITHM_INDIRECT,          "INDIRECT" },
	{ DNSSEC_KEY_ALGORITHM_PRIVATEDNS,        "PRIVATEDNS" },
	{ DNSSEC_KEY_ALGORITHM_PRIVATEOID,        "PRIVATEOID" },
	{ 0, NULL }
};

_public_
const knot_lookup_t knot_svcb_param_names[] = {
	{ KNOT_SVCB_PARAM_MANDATORY, "mandatory" },
	{ KNOT_SVCB_PARAM_ALPN,      "alpn" },
	{ KNOT_SVCB_PARAM_NDALPN,    "no-default-alpn" },
	{ KNOT_SVCB_PARAM_PORT,      "port" },
	{ KNOT_SVCB_PARAM_IPV4HINT,  "ipv4hint" },
	{ KNOT_SVCB_PARAM_ECH,       "ech" },
	{ KNOT_SVCB_PARAM_IPV6HINT,  "ipv6hint" },
	{ KNOT_SVCB_PARAM_DOHPATH,   "dohpath" },
	{ KNOT_SVCB_PARAM_OHTTP,     "ohttp" },
	{ 0, NULL }
};

_public_
const knot_lookup_t knot_deleg_info_names[] = {
	{ KNOT_DELEG_INFO_MANDATORY,   "mandatory" },
	{ KNOT_DELEG_INFO_IPV4,        "server-ipv4" },
	{ KNOT_DELEG_INFO_IPV6,        "server-ipv6" },
	{ KNOT_DELEG_INFO_NAME,        "server-name" },
	{ KNOT_DELEG_INFO_INCLUDE,     "include-delegi" },
	{ 0, NULL }
};

_public_
const knot_lookup_t knot_edns_opt_names[] = {
	{ KNOT_EDNS_OPTION_NSID,          "NSID" },
	{ KNOT_EDNS_OPTION_CLIENT_SUBNET, "ECS" },
	{ KNOT_EDNS_OPTION_EXPIRE,        "EXPIRE" },
	{ KNOT_EDNS_OPTION_COOKIE,        "COOKIE" },
	{ KNOT_EDNS_OPTION_TCP_KEEPALIVE, "KEEPALIVE" },
	{ KNOT_EDNS_OPTION_PADDING,       "PADDING" },
	{ KNOT_EDNS_OPTION_CHAIN,         "CHAIN" },
	{ KNOT_EDNS_OPTION_EDE,           "EDE" },
	{ KNOT_EDNS_OPTION_ZONEVERSION,   "ZONEVERSION" },
	{ 0, NULL }
};
