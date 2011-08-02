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
