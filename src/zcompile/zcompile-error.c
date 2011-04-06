#include "zcompile/zcompile-error.h"

#include "common/errors.h"

/*! \brief Table linking error messages to error codes. */
const error_table_t knot_zcompile_error_msgs[KNOT_ZCOMPILE_ERROR_COUNT] = {

	/* Mapped errors. */
	{KNOT_ZCOMPILE_EOK, "OK"},
	{KNOT_ZCOMPILE_ENOMEM, "Not enough memory."},
	{KNOT_ZCOMPILE_EINVAL, "Invalid parameter passed."},
	{KNOT_ZCOMPILE_ENOTSUP, "Parameter not supported."},
	{KNOT_ZCOMPILE_EBUSY, "Requested resource is busy."},
	{KNOT_ZCOMPILE_EAGAIN,
	 "The system lacked the necessary resource, try again."},
	{KNOT_ZCOMPILE_EACCES,
	 "Permission to perform requested operation is denied."},
	{KNOT_ZCOMPILE_ECONNREFUSED, "Connection is refused."},
	{KNOT_ZCOMPILE_EISCONN, "Already connected."},
	{KNOT_ZCOMPILE_EADDRINUSE, "Address already in use."},
	{KNOT_ZCOMPILE_ENOENT, "Resource not found."},
	{KNOT_ZCOMPILE_ERANGE, "Value is out of range."},

	/* Custom errors. */
	{KNOT_ZCOMPILE_ERROR, "Generic error."},
	{KNOT_ZCOMPILE_EBRDATA, "Malformed RDATA."},
	{KNOT_ZCOMPILE_ESOA, "Multiple SOA records."},
	{KNOT_ZCOMPILE_EBADSOA, "SOA record has different owner "
	 "than in config - parser will not continue!"},
	{KNOT_ZCOMPILE_EBADNODE, "Error handling node."},
	{KNOT_ZCOMPILE_EZONEINVAL, "Invalid zone file."},
	{KNOT_ZCOMPILE_EPARSEFAIL, "Parser failed."},
	{KNOT_ZCOMPILE_ENOIPV6, "IPv6 support disabled."},
	{KNOT_ZCOMPILE_ESYNT, "Parser syntactic error."},
	{KNOT_ZCOMPILE_ERROR, 0}
};
