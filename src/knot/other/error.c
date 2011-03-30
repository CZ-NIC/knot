#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "knot/other/error.h"

/*! \brief Error lookup table. */
typedef struct error_table_t {
	knot_error_t id;
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
static const error_table_t knot_error_msgs[] = {

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
        {KNOT_EADDRINVAL, "Invalid address."},
        {KNOT_EZONEINVAL, "Invalid zone file."},
        {KNOT_ENOTRUNNING, "Resource is not running."},
        {KNOT_ENOIPV6, "IPv6 support disabled."},
        {KNOT_ERROR, 0}
};

const char *knot_strerror(int errno)
{
	const error_table_t *msg = error_lookup_by_id(knot_error_msgs,
	                                              errno);
	if (msg != 0) {
		return msg->name;
	} else {
		return "Unknown error.";
	}
}

int _knot_map_errno(int arg0, ...)
{
	/* Iterate all variable-length arguments. */
	va_list ap;
	va_start(ap, arg0);

	/* KNOT_ERROR serves as a sentinel. */
	for (int c = arg0; c != KNOT_ERROR; c = va_arg(ap, int)) {

		/* Error code matches with mapped. */
		if (c == errno) {
			/* Return negative value of the code. */
			return -abs(c);
		}
	}
	va_end(ap);

	/* Fallback error code. */
	return KNOT_ERROR;
}

