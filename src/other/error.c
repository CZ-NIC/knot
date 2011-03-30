#include <stdarg.h>
#include <stdio.h>

#include "other/error.h"

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
	{KNOT_EOK, "OK"},
        {KNOT_ERROR, "Generic error."},
        {KNOT_ENOMEM, "Not enough memory."},
        {KNOT_EINVAL, "Invalid parameter passsed."},
        {KNOT_ENOTSUP, "Parameter not supported."},
        {KNOT_EBUSY,   "Requested resource is busy."},
        {KNOT_EAGAIN,  "The system lacked the necessary resource, try again."},
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

int _knot_map_errno(int err, ...)
{
	/* Iterate all variable-length arguments. */
	va_list ap;
	va_start(ap, err);

	/* KNOT_ERROR serves as a sentinel. */
	for (int c = va_arg(ap, int); c != KNOT_ERROR; c = va_arg(ap, int)) {

		/* Error code matches with mapped. */
		if (c == err) {
			return c;
		}
	}
	va_end(ap);

	/* Fallback error code. */
	return KNOT_ERROR;
}

