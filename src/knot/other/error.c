#include "knot/other/error.h"
#include "common/errors.h"

const error_table_t knot_error_msgs[] = {

	/* Mapped errors. */
	{KNOTD_EOK, "OK"},
	{KNOTD_ENOMEM, "Not enough memory."},
	{KNOTD_EINVAL, "Invalid parameter passed."},
	{KNOTD_ENOTSUP, "Parameter not supported."},
	{KNOTD_EBUSY,   "Requested resource is busy."},
	{KNOTD_EAGAIN,  "The system lacked the necessary resource, try again."},
	{KNOTD_EACCES,  "Permission to perform requested operation is denied."},
	{KNOTD_ECONNREFUSED, "Connection is refused."},
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
	{KNOTD_ERROR, 0}
};
