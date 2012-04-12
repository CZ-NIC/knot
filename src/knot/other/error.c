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

#include "knot/other/error.h"
#include "common/errors.h"

const error_table_t knotd_error_msgs[] = {

	/* Mapped errors. */
	{KNOTD_EOK, "OK"},
	{KNOTD_ENOMEM, "Not enough memory."},
	{KNOTD_EINVAL, "Invalid parameter passed."},
	{KNOTD_ENOTSUP, "Parameter not supported."},
	{KNOTD_EBUSY,   "Requested resource is busy."},
	{KNOTD_EAGAIN,  "The system lacked the necessary resource, try again."},
	{KNOTD_EACCES,  "Operation not permitted."},
	{KNOTD_ECONNREFUSED, "Connection refused."},
	{KNOTD_EISCONN, "Already connected."},
	{KNOTD_EADDRINUSE, "Address already in use."},
	{KNOTD_ENOENT, "Resource not found."},
	{KNOTD_ERANGE, "Value is out of range."},

	/* Custom errors. */
	{KNOTD_ERROR, "Generic error."},
	{KNOTD_EZONEINVAL, "Invalid zone file."},
	{KNOTD_ENOTRUNNING, "Resource is not running."},
	{KNOTD_EPARSEFAIL, "Parser failed."},
	{KNOTD_ENOIPV6, "IPv6 support disabled."},
	{KNOTD_EMALF, "Malformed data."},
	{KNOTD_ESPACE, "Not enough space provided."},
        {KNOTD_EEXPIRED, "Resource is expired."},
	{KNOTD_ERROR, 0}
};
