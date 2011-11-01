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

#include "zcompile/zcompile-error.h"

#include "common/errors.h"

/*! \brief Table linking error messages to error codes. */
const error_table_t knot_zcompile_error_msgs[KNOTDZCOMPILE_ERROR_COUNT] = {

	/* Mapped errors. */
	{KNOTDZCOMPILE_EOK, "OK"},
	{KNOTDZCOMPILE_ENOMEM, "Not enough memory."},
	{KNOTDZCOMPILE_EINVAL, "Invalid parameter passed."},
	{KNOTDZCOMPILE_ENOTSUP, "Parameter not supported."},
	{KNOTDZCOMPILE_EBUSY, "Requested resource is busy."},
	{KNOTDZCOMPILE_EAGAIN,
	 "The system lacked the necessary resource, try again."},
	{KNOTDZCOMPILE_EACCES,
	 "Permission to perform requested operation is denied."},
	{KNOTDZCOMPILE_ECONNREFUSED, "Connection is refused."},
	{KNOTDZCOMPILE_EISCONN, "Already connected."},
	{KNOTDZCOMPILE_EADDRINUSE, "Address already in use."},
	{KNOTDZCOMPILE_ENOENT, "Resource not found."},
	{KNOTDZCOMPILE_ERANGE, "Value is out of range."},

	/* Custom errors. */
	{KNOTDZCOMPILE_ERROR, "Generic error."},
	{KNOTDZCOMPILE_EBRDATA, "Malformed RDATA."},
	{KNOTDZCOMPILE_ESOA, "Multiple SOA records."},
	{KNOTDZCOMPILE_EBADSOA, "SOA record has different owner "
	 "than in config - parser will not continue!"},
	{KNOTDZCOMPILE_EBADNODE, "Error handling node."},
	{KNOTDZCOMPILE_EZONEINVAL, "Invalid zone file."},
	{KNOTDZCOMPILE_EPARSEFAIL, "Parser failed."},
	{KNOTDZCOMPILE_ENOIPV6, "IPv6 support disabled."},
	{KNOTDZCOMPILE_ESYNT, "Parser syntactic error."},
	{KNOTDZCOMPILE_ERROR, 0}
};
