#include "knot/server/axfr-in.h"

/*----------------------------------------------------------------------------*/

int axfrin_create_soa_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size)
{
	return KNOT_ERROR;
}

/*----------------------------------------------------------------------------*/

int axfrin_transfer_needed(const dnslib_zone_t *zone,
                           const dnslib_packet_t *soa_response)
{
	return KNOT_ERROR;
}

/*----------------------------------------------------------------------------*/

int axfrin_create_axfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size)
{
	return KNOT_ERROR;
}
