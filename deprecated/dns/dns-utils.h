#ifndef DNS_UTILS
#define DNS_UTILS

#include <ldns/rdata.h>
#include "common.h"

uint dnsu_subdomain_labels( const ldns_rdf *sub, const ldns_rdf *parent );

#endif /* DNS_UTILS */
