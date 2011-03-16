#include "dnslib/error.h"
#include "dnslib/utils.h"

static const dnslib_lookup_table_t dnslib_error_msgs[] = {
	{DNSLIB_EOK, "OK"},
	{DNSLIB_ERROR, "General dnslib error."},
	{DNSLIB_ENOMEM, "Not enough memory."},
	{DNSLIB_EBADARG, "Wrong argument supported."},
	{DNSLIB_EFEWDATA, "Not enough data to parse."},
	{DNSLIB_ESPACE, "Not enough space provided."},
	{DNSLIB_EMALF, "Malformed data."}
};

/*----------------------------------------------------------------------------*/

const char *dnslib_strerror(dnslib_error_t errno)
{
	dnslib_lookup_table_t *msg = dnslib_lookup_by_id(dnslib_error_msgs,
							 errno);
	if (msg != NULL) {
		return msg->name;
	} else {
		return "Unknown error.";
	}
}

