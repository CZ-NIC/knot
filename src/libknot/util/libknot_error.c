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

#include "util/error.h"
#include "common/errors.h"

const error_table_t knot_error_msgs[] = {
	{KNOT_EOK, "OK"},
	{KNOT_ERROR, "General error."},
	{KNOT_ENOMEM, "Not enough memory."},
	{KNOT_ENOTSUP, "Operation not supported."},
	{KNOT_EAGAIN, "OS lacked necessary resources."},
	{KNOT_ERANGE, "Value is out of range."},
	{KNOT_EBADARG, "Wrong argument supplied."},
	{KNOT_EFEWDATA, "Not enough data to parse."},
	{KNOT_ESPACE, "Not enough space provided."},
	{KNOT_EMALF, "Malformed data."},
	{KNOT_ENOENT, "Resource not found."},
	{KNOT_EACCES,  "Permission to perform requested operation is denied."},
	{KNOT_ECRYPTO, "Error in crypto library."},
	{KNOT_ENSEC3PAR, "Missing or wrong NSEC3PARAM record."},
	{KNOT_ENSEC3CHAIN, "Missing or wrong NSEC3 chain in the zone."},
	{KNOT_EBADZONE, "Domain name does not belong to the given zone."},
	{KNOT_EHASH, "Error in hash table."},
	{KNOT_EZONEIN, "Error inserting zone."},
	{KNOT_ENOZONE, "No such zone found."},
	{KNOT_ENONODE, "No such node in zone found."},
	{KNOT_ENORRSET, "No such RRSet found."},
	{KNOT_EDNAMEPTR, "Domain name pointer larger than allowed."},
	{KNOT_EPAYLOAD, "Payload in OPT RR larger than max wire size."},
	{KNOT_ECRC, "CRC check failed."},
	{KNOT_EPREREQ, "UPDATE prerequisity not met."},
	{KNOT_ENOXFR, "Transfer was not sent."},
	{KNOT_ENOIXFR, "Transfer is not IXFR (is in AXFR format)."},
	{KNOT_EXFRREFUSED, "Zone transfer refused by the server."},
	{KNOT_TSIG_EBADSIG, "Failed to verify TSIG MAC." },
	{KNOT_TSIG_EBADKEY, "TSIG key not recognized or invalid." },
	{KNOT_TSIG_EBADTIME, "TSIG signing time out of range." },
	{KNOT_ECONN, "Connection reset."},
	{KNOT_EIXFRSPACE, "IXFR reply did not fit in."},
	{KNOT_ECNAME, "CNAME loop found in zone."},
	{KNOT_ENODIFF, "Cannot create zone diff."},

	{ZSCANNER_UNCOVERED_STATE, "General scanner error!"},
	{ZSCANNER_ELEFT_PARENTHESIS, "Too many left parentheses!"},
	{ZSCANNER_ERIGHT_PARENTHESIS, "Too many right parentheses!"},
	{ZSCANNER_EUNSUPPORTED_TYPE, "Unsupported record type!"},
	{ZSCANNER_EBAD_PREVIOUS_OWNER, "Previous owner is invalid!"},
	{ZSCANNER_EBAD_DNAME_CHAR, "Bad domain name character!"},
	{ZSCANNER_EBAD_OWNER, "Owner is invalid!"},
	{ZSCANNER_ELABEL_OVERFLOW, "Maximal domain name label length has exceeded!"},
	{ZSCANNER_EDNAME_OVERFLOW, "Maximal domain name length has exceeded!"},
	{ZSCANNER_ENUMBER64_OVERFLOW, "Number is too big!"},
	{ZSCANNER_ENUMBER32_OVERFLOW, "Number is bigger than 32 bits!"},
	{ZSCANNER_ENUMBER16_OVERFLOW, "Number is bigger than 16 bits!"},
	{ZSCANNER_ENUMBER8_OVERFLOW, "Number is bigger than 8 bits!"},
	{ZSCANNER_EBAD_ORIGIN, "Invalid zone origin!"},
	{ZSCANNER_ERDATA_OVERFLOW, "Maximal record data length has exceeded!"},
	{ZSCANNER_EBAD_ADDRESS_CHAR, "Bad address character!"},
	{ZSCANNER_EBAD_IPV4, "Bad IPv4 address!"},
	{ZSCANNER_EBAD_IPV6, "Bad IPv6 address!"},
	{ZSCANNER_EBAD_RDATA, "Bad record data!"},
	{ZSCANNER_EBAD_HEX_CHAR, "Bad hexadecimal character!"},
	{ZSCANNER_EBAD_BASE64_CHAR, "Bad Base64 character!"},
	{ZSCANNER_EBAD_BASE32HEX_CHAR, "Bad Base32hex character!"},
	{ZSCANNER_EBAD_REST, "Unexpected data!"},
	{ZSCANNER_EBAD_TIMESTAMP_CHAR, "Bad timestamp character!"},
	{ZSCANNER_EBAD_TIMESTAMP_LENGTH, "Bad timestamp length!"},
	{ZSCANNER_EBAD_TIMESTAMP, "Bad timestamp!"},
	{ZSCANNER_EBAD_DATE, "Bad date!"},
	{ZSCANNER_EBAD_TIME, "Bad time!"},
	{ZSCANNER_EBAD_BITMAP, "Bad bitmap!"},
	{ZSCANNER_ETEXT_OVERFLOW, "Text is too long!"},

	{KNOT_ERROR, 0}
};
