#include "knot/other/error.h"
#include "common/errors.h"

const error_table_t knot_error_msgs[] = {

	/* Mapped errors. */
	{KNOTDEOK, "OK"},
	{KNOTDENOMEM, "Not enough memory."},
	{KNOTDEINVAL, "Invalid parameter passed."},
	{KNOTDENOTSUP, "Parameter not supported."},
	{KNOTDEBUSY,   "Requested resource is busy."},
	{KNOTDEAGAIN,  "The system lacked the necessary resource, try again."},
	{KNOTDEACCES,  "Permission to perform requested operation is denied."},
	{KNOTDECONNREFUSED, "Connection is refused."},
	{KNOTDEISCONN, "Already connected."},
	{KNOTDEADDRINUSE, "Address already in use."},
	{KNOTDENOENT, "Resource not found."},
	{KNOTDERANGE, "Value is out of range."},

	/* Custom errors. */
	{KNOTDERROR, "Generic error."},
	{KNOTDEZONEINVAL, "Invalid zone file."},
	{KNOTDENOTRUNNING, "Resource is not running."},
	{KNOTDEPARSEFAIL, "Parser failed."},
	{KNOTDENOIPV6, "IPv6 support disabled."},
	{KNOTDEMALF, "Malformed data."},
	{KNOTDESPACE, "Not enough space provided."},
	{KNOTDERROR, 0}
};
