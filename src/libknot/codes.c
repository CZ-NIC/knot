/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
const knot_lookup_t knot_dnssec_alg_names[] = {
	{ KNOT_DNSSEC_ALG_RSAMD5,             "RSAMD5" },
	{ KNOT_DNSSEC_ALG_DH,                 "DH" },
	{ KNOT_DNSSEC_ALG_DSA,                "DSA" },
	{ KNOT_DNSSEC_ALG_RSASHA1,            "RSASHA1" },
	{ KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1,     "DSA_NSEC3_SHA1" },
	{ KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1, "RSASHA1_NSEC3_SHA1" },
	{ KNOT_DNSSEC_ALG_RSASHA256,          "RSASHA256" },
	{ KNOT_DNSSEC_ALG_RSASHA512,          "RSASHA512" },
	{ KNOT_DNSSEC_ALG_ECC_GOST,           "ECC_GOST" },
	{ KNOT_DNSSEC_ALG_ECDSAP256SHA256,    "ECDSAP256SHA256" },
	{ KNOT_DNSSEC_ALG_ECDSAP384SHA384,    "ECDSAP384SHA384" },
	{ KNOT_DNSSEC_ALG_ED25519,            "ED25519" },
	{ KNOT_DNSSEC_ALG_ED448,              "ED448" },
	{ KNOT_DNSSEC_ALG_INDIRECT,           "INDIRECT" },
	{ KNOT_DNSSEC_ALG_PRIVATEDNS,         "PRIVATEDNS" },
	{ KNOT_DNSSEC_ALG_PRIVATEOID,         "PRIVATEOID" },
	{ 0, NULL }
};
