#include "knot/other/error.h"
#include "common/errors.h"

const error_table_t knot_error_msgs[] = {

	/* Mapped errors. */
	{KNOT_EOK, "OK"},
	{KNOT_ENOMEM, "Not enough memory."},
	{KNOT_EINVAL, "Invalid parameter passed."},
	{KNOT_ENOTSUP, "Parameter not supported."},
	{KNOT_EBUSY,   "Requested resource is busy."},
	{KNOT_EAGAIN,  "The system lacked the necessary resource, try again."},
	{KNOT_EACCES,  "Permission to perform requested operation is denied."},
	{KNOT_ECONNREFUSED, "Connection is refused."},
	{KNOT_EISCONN, "Already connected."},
	{KNOT_EADDRINUSE, "Address already in use."},
	{KNOT_ENOENT, "Resource not found."},
	{KNOT_ERANGE, "Value is out of range."},

	/* Custom errors. */
	{KNOT_ERROR, "Generic error."},
	{KNOT_EZONEINVAL, "Invalid zone file."},
	{KNOT_ENOTRUNNING, "Resource is not running."},
	{KNOT_EPARSEFAIL, "Parser failed."},
	{KNOT_ENOIPV6, "IPv6 support disabled."},
	{KNOT_EMALF, "Malformed data."},
	{KNOT_ESPACE, "Not enough space provided."},
	{KNOT_ERROR, 0}
};
