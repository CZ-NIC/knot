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

#include "common/errcode.h"
#include "common/errors.h"

const error_table_t knot_error_msgs[] = {
	{KNOT_EOK, "OK"},
	
	/* TSIG errors. */
	{KNOT_TSIG_EBADSIG, "Failed to verify TSIG MAC." },
	{KNOT_TSIG_EBADKEY, "TSIG key not recognized or invalid." },
	{KNOT_TSIG_EBADTIME, "TSIG signing time out of range." },
	
	/* Directly mapped error codes. */
	{KNOT_ENOMEM, "Not enough memory."},
	{KNOT_EINVAL, "Invalid parameter."},
	{KNOT_ENOTSUP, "Operation not supported."},
	{KNOT_EBUSY,   "Requested resource is busy."},
	{KNOT_EAGAIN, "OS lacked necessary resources."},
	{KNOT_EACCES,  "Operation not permitted."},
	{KNOT_ECONNREFUSED, "Connection refused."},
	{KNOT_EISCONN, "Already connected."},
	{KNOT_EADDRINUSE, "Address already in use."},
	{KNOT_ENOENT, "Resource not found."},
	{KNOT_ERANGE, "Value is out of range."},
	
	/* General errors. */
	{KNOT_ERROR, "General error."},
	{KNOT_ENOTRUNNING, "Resource is not running."},
	{KNOT_EPARSEFAIL, "Parser failed."},
	{KNOT_ENOIPV6, "IPv6 support disabled."},
	{KNOT_EEXPIRED, "Resource is expired."},
	{KNOT_EUPTODATE, "Zone is up-to-date."},
	{KNOT_EFEWDATA, "Not enough data to parse."},
	{KNOT_ESPACE, "Not enough space provided."},
	{KNOT_EMALF, "Malformed data."},
	{KNOT_ECRYPTO, "Error in crypto library."},
	{KNOT_ENSEC3PAR, "Missing or wrong NSEC3PARAM record."},
	{KNOT_ENSEC3CHAIN, "Missing or wrong NSEC3 chain in the zone."},
	{KNOT_EBADZONE, "Name does not belong to the zone."},
	{KNOT_EHASH, "Error in hash table."},
	{KNOT_EZONEINVAL, "Invalid zone file."},
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
	{KNOT_EXFRDENIED, "Transfer not allowed."},
	{KNOT_ECONN, "Connection reset."},
	{KNOT_EIXFRSPACE, "IXFR reply did not fit in."},
	{KNOT_ECNAME, "CNAME loop found in zone."},
	{KNOT_ENODIFF, "Cannot create zone diff."},

	{KNOT_ERROR, 0}
};
