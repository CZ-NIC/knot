#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "zoneparser/zcompile_error.h"

/*! \brief Error lookup table. */
typedef struct error_table_t {
	knot_zcompile_error_t id;
	const char *name;
} error_table_t;

/*!
 * \brief Looks up the given id in the lookup table.
 *
 * \param table Lookup table.
 * \param id ID to look up.
 *
 * \return Item in the lookup table with the given id or NULL if no such is
 *         present.
 */
const error_table_t *error_lookup_by_id(const error_table_t *table, int id)
{
	while (table->name != 0) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return 0;
}

/*! \brief Table linking error messages to error codes. */
static const error_table_t knot_zcompile_error_msgs[] = {

	/* Mapped errors. */
	{KNOT_ZCOMPILE_EOK, "OK"},
	{KNOT_ZCOMPILE_ENOMEM, "Not enough memory."},
	{KNOT_ZCOMPILE_EINVAL, "Invalid parameter passed."},
	{KNOT_ZCOMPILE_ENOTSUP, "Parameter not supported."},
	{KNOT_ZCOMPILE_EBUSY,   "Requested resource is busy."},
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
	{KNOT_ZCOMPILE_EZONEINVAL, "Invalid zone file."},
	{KNOT_ZCOMPILE_EPARSEFAIL, "Parser failed."},
	{KNOT_ZCOMPILE_ENOIPV6, "IPv6 support disabled."},
	{KNOT_ZCOMPILE_ERROR, 0}
};

const char *knot_zcompile_strerror(int errno)
{
	const error_table_t *msg = error_lookup_by_id(knot_zcompile_error_msgs,
						      errno);
	if (msg != 0) {
		return msg->name;
	} else {
		return "Unknown error.";
	}
}

int _knot_zcompile_map_errno(int arg0, ...)
{
	/* Iterate all variable-length arguments. */
	va_list ap;
	va_start(ap, arg0);

	/* KNOT_ZCOMPILE_ERROR serves as a sentinel. */
	for (int c = arg0; c != KNOT_ZCOMPILE_ERROR; c = va_arg(ap, int)) {

		/* Error code matches with mapped. */
		if (c == errno) {
			/* Return negative value of the code. */
			return -abs(c);
		}
	}
	va_end(ap);

	/* Fallback error code. */
	return KNOT_ZCOMPILE_ERROR;
}

