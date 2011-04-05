#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/errors.h"

/*!
 * \brief Looks up the given id in the lookup table.
 *
 * \param table Lookup table.
 * \param id ID to look up.
 *
 * \return Item in the lookup table with the given id or NULL if no such is
 *         present.
 */
static const error_table_t *error_lookup_by_id(const error_table_t *table,
                                               int id)
{
	while (table->name != 0) {
		if (table->id == id) {
			return table;
		}
		table++;
	}

	return 0;
}

const char *error_to_str(error_table_t *table, int errno)
{
	const error_table_t *msg = error_lookup_by_id(table, errno);
	if (msg != 0) {
		return msg->name;
	} else {
		return "Unknown error.";
	}
}

int _map_errno(int fallback_value, int arg0, ...)
{
	/* Iterate all variable-length arguments. */
	va_list ap;
	va_start(ap, arg0);

	/* KNOT_ERROR serves as a sentinel. */
	for (int c = arg0; c != 0; c = va_arg(ap, int)) {

		/* Error code matches with mapped. */
		if (c == errno) {
			/* Return negative value of the code. */
			return -abs(c);
		}
	}
	va_end(ap);

	/* Fallback error code. */
	return fallback_value;
}
