#include "dnslib/query.h"

/*----------------------------------------------------------------------------*/

int dnslib_query_dnssec_requested(const dnslib_packet_t *query)
{
	return dnslib_edns_do(&query->opt_rr);
}

/*----------------------------------------------------------------------------*/

int dnslib_query_nsid_requested(const dnslib_packet_t *query)
{
	return dnslib_edns_has_option(&query->opt_rr, EDNS_OPTION_NSID);
}
