/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <libknot/consts.h>

knot_lookup_table_t knot_opcode_names[] = {
	{ KNOT_OPCODE_QUERY,  "QUERY" },
	{ KNOT_OPCODE_IQUERY, "IQUERY" },
	{ KNOT_OPCODE_STATUS, "STATUS" },
	{ KNOT_OPCODE_NOTIFY, "NOTIFY" },
	{ KNOT_OPCODE_UPDATE, "UPDATE" },
	{ 0, NULL }
};

knot_lookup_table_t knot_rcode_names[] = {
	{ KNOT_RCODE_NOERROR,  "NOERROR" },
	{ KNOT_RCODE_FORMERR,  "FORMERR" },
	{ KNOT_RCODE_SERVFAIL, "SERVFAIL" },
	{ KNOT_RCODE_NXDOMAIN, "NXDOMAIN" },
	{ KNOT_RCODE_NOTIMPL,  "NOTIMPL" },
	{ KNOT_RCODE_REFUSED,  "REFUSED" },
	{ KNOT_RCODE_YXDOMAIN, "YXDOMAIN" },
	{ KNOT_RCODE_YXRRSET,  "YXRRSET" },
	{ KNOT_RCODE_NXRRSET,  "NXRRSET" },
	{ KNOT_RCODE_NOTAUTH,  "NOTAUTH" },
	{ KNOT_RCODE_NOTZONE,  "NOTZONE" },
	{ KNOT_RCODE_BADVERS,  "BADVERS" },
	{ 0, NULL }
};

knot_lookup_table_t knot_tsig_err_names[] = {
	{ KNOT_TSIG_ERR_BADSIG,   "BADSIG" },
	{ KNOT_TSIG_ERR_BADKEY,   "BADKEY" },
	{ KNOT_TSIG_ERR_BADTIME,  "BADTIME" },
	{ KNOT_TSIG_ERR_BADTRUNC, "BADTRUNC" },
	{ 0, NULL }
};

knot_lookup_table_t knot_tkey_err_names[] = {
	{ KNOT_TKEY_ERR_BADMODE,  "BADMODE" },
	{ KNOT_TKEY_ERR_BADNAME,  "BADNAME" },
	{ KNOT_TKEY_ERR_BADALG,   "BADALG" },
	{ 0, NULL }
};

knot_lookup_table_t knot_tsig_alg_names[] = {
	{ KNOT_TSIG_ALG_HMAC_MD5,    "hmac-md5" },
	{ KNOT_TSIG_ALG_HMAC_SHA1,   "hmac-sha1" },
	{ KNOT_TSIG_ALG_HMAC_SHA224, "hmac-sha224" },
	{ KNOT_TSIG_ALG_HMAC_SHA256, "hmac-sha256" },
	{ KNOT_TSIG_ALG_HMAC_SHA384, "hmac-sha384" },
	{ KNOT_TSIG_ALG_HMAC_SHA512, "hmac-sha512" },
	{ KNOT_TSIG_ALG_NULL, NULL }
};

knot_lookup_table_t knot_tsig_alg_dnames_str[] = {
	{ KNOT_TSIG_ALG_GSS_TSIG,    "gss-tsig." },
	{ KNOT_TSIG_ALG_HMAC_MD5,    "hmac-md5.sig-alg.reg.int." },
	{ KNOT_TSIG_ALG_HMAC_SHA1,   "hmac-sha1." },
	{ KNOT_TSIG_ALG_HMAC_SHA224, "hmac-sha224." },
	{ KNOT_TSIG_ALG_HMAC_SHA256, "hmac-sha256." },
	{ KNOT_TSIG_ALG_HMAC_SHA384, "hmac-sha384." },
	{ KNOT_TSIG_ALG_HMAC_SHA512, "hmac-sha512." },
	{ KNOT_TSIG_ALG_NULL, NULL }
};

knot_lookup_table_t knot_tsig_alg_dnames[] = {
        { KNOT_TSIG_ALG_GSS_TSIG,    "\x08" "gss-tsig" },
        { KNOT_TSIG_ALG_HMAC_MD5,    "\x08" "hmac-md5" "\x07" "sig-alg" "\x03" "reg" "\x03" "int" },
	{ KNOT_TSIG_ALG_HMAC_SHA1,   "\x09" "hmac-sha1" },
	{ KNOT_TSIG_ALG_HMAC_SHA224, "\x0B" "hmac-sha224" },
	{ KNOT_TSIG_ALG_HMAC_SHA256, "\x0B" "hmac-sha256" },
	{ KNOT_TSIG_ALG_HMAC_SHA384, "\x0B" "hmac-sha384" },
	{ KNOT_TSIG_ALG_HMAC_SHA512, "\x0B" "hmac-sha512" },
	{ KNOT_TSIG_ALG_NULL, NULL }
};

knot_lookup_table_t knot_dnssec_alg_names[] = {
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
    //dipapadop: NSEC5
    { KNOT_DNSSEC_ALG_NSEC5_RSASHA256,    "NSEC5_RSASHA256" },
	{ 0, NULL }
};

size_t knot_tsig_digest_length(const uint8_t algorithm)
{
	switch (algorithm) {
	case KNOT_TSIG_ALG_GSS_TSIG:
		return KNOT_TSIG_ALG_DIG_LENGTH_GSS_TSIG;
	case KNOT_TSIG_ALG_HMAC_MD5:
		return KNOT_TSIG_ALG_DIG_LENGTH_HMAC_MD5;
	case KNOT_TSIG_ALG_HMAC_SHA1:
		return KNOT_TSIG_ALG_DIG_LENGTH_SHA1;
	case KNOT_TSIG_ALG_HMAC_SHA224:
		return KNOT_TSIG_ALG_DIG_LENGTH_SHA224;
	case KNOT_TSIG_ALG_HMAC_SHA256:
		return KNOT_TSIG_ALG_DIG_LENGTH_SHA256;
	case KNOT_TSIG_ALG_HMAC_SHA384:
		return KNOT_TSIG_ALG_DIG_LENGTH_SHA384;
	case KNOT_TSIG_ALG_HMAC_SHA512:
		return KNOT_TSIG_ALG_DIG_LENGTH_SHA512;
	default:
		return 0;
	}
}

bool knot_dnssec_algorithm_is_zonesign(uint8_t algorithm, bool nsec3_enabled)
{
	switch (algorithm) {
	// NSEC only
	case KNOT_DNSSEC_ALG_DSA:
	case KNOT_DNSSEC_ALG_RSASHA1:
		return !nsec3_enabled;

	// NSEC3 only
	case KNOT_DNSSEC_ALG_DSA_NSEC3_SHA1:
	case KNOT_DNSSEC_ALG_RSASHA1_NSEC3_SHA1:
		return true; // allow even with NSEC
            
    // dipapado: NSEC5 only
    case KNOT_DNSSEC_ALG_NSEC5_RSASHA256:
        return true;

	// both NSEC and NSEC3
	case KNOT_DNSSEC_ALG_RSASHA256:
	case KNOT_DNSSEC_ALG_RSASHA512:
	case KNOT_DNSSEC_ALG_ECC_GOST:
	case KNOT_DNSSEC_ALG_ECDSAP256SHA256:
	case KNOT_DNSSEC_ALG_ECDSAP384SHA384:
		return true;

	// unsupported or unknown
	default:
		return false;
	}
}
