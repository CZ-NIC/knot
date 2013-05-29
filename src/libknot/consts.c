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

#include <config.h>
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
	{ KNOT_RCODE_BADSIG,   "BADSIG" },
	{ KNOT_RCODE_BADKEY,   "BADKEY" },
	{ KNOT_RCODE_BADTIME,  "BADTIME" },
	{ KNOT_RCODE_BADMODE,  "BADMODE" },
	{ KNOT_RCODE_BADNAME,  "BADNAME" },
	{ KNOT_RCODE_BADALG,   "BADALG" },
	{ KNOT_RCODE_BADTRUNC, "BADTRUNC" },
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

knot_lookup_table_t knot_tsig_alg_domain_names[] = {
	{ KNOT_TSIG_ALG_GSS_TSIG,    "gss-tsig." },
	{ KNOT_TSIG_ALG_HMAC_MD5,    "hmac-md5.sig-alg.reg.int." },
	{ KNOT_TSIG_ALG_HMAC_SHA1,   "hmac-sha1." },
	{ KNOT_TSIG_ALG_HMAC_SHA224, "hmac-sha224." },
	{ KNOT_TSIG_ALG_HMAC_SHA256, "hmac-sha256." },
	{ KNOT_TSIG_ALG_HMAC_SHA384, "hmac-sha384." },
	{ KNOT_TSIG_ALG_HMAC_SHA512, "hmac-sha512." },
	{ KNOT_TSIG_ALG_NULL, NULL }
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

size_t knot_ds_digest_length(const uint8_t algorithm)
{
	switch (algorithm) {
	case KNOT_DS_ALG_SHA1:
		return KNOT_DS_DIGEST_LEN_SHA1;
	case KNOT_DS_ALG_SHA256:
		return KNOT_DS_DIGEST_LEN_SHA256;
	case KNOT_DS_ALG_GOST:
		return KNOT_DS_DIGEST_LEN_GOST;
	case KNOT_DS_ALG_SHA384:
		return KNOT_DS_DIGEST_LEN_SHA384;
	default:
		return 0;
	}
}
