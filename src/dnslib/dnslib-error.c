#include "dnslib/error.h"
#include "dnslib/utils.h"

#include "common/errors.h"

const error_table_t dnslib_error_msgs[DNSLIB_ERROR_COUNT] = {
	{DNSLIB_EOK, "OK"},
	{DNSLIB_ERROR, "General dnslib error."},
	{DNSLIB_ENOMEM, "Not enough memory."},
	{DNSLIB_EBADARG, "Wrong argument supported."},
	{DNSLIB_EFEWDATA, "Not enough data to parse."},
	{DNSLIB_ESPACE, "Not enough space provided."},
	{DNSLIB_EMALF, "Malformed data."},
	{DNSLIB_ECRYPTO, "Error in crypto library."},
	{DNSLIB_ENSEC3PAR, "Missing or wrong NSEC3PARAM record."},
	{DNSLIB_EBADZONE, "Domain name does not belong to the given zone."},
	{DNSLIB_EHASH, "Error in hash table."},
	{DNSLIB_EZONEIN, "Error inserting zone."},
	{DNSLIB_ENOZONE, "No such zone found."},
	{DNSLIB_EDNAMEPTR, "Domain name pointer larger than allowed."},
	{DNSLIB_ERROR, 0}
};
