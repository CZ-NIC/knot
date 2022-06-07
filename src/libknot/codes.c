/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "libknot/attribute.h"
#include "libknot/codes.h"
#include "libknot/consts.h"
#include "libdnssec/key.h"

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
	{ 0, NULL }
};
