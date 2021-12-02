#include <assert.h>
#include <netinet/ip.h> 

#include "libknot/attribute.h"
#include "libknot/error.h"
#include "libknot/quic/shared.h"

_public_
int knot_str_to_alpn(gnutls_datum_t *dest, const size_t dest_len,
                     const char *alpn)
{
	assert(dest && dest_len && alpn);
	gnutls_datum_t *dest_it = dest;
	const gnutls_datum_t *dest_end = (dest + dest_len);
	const char *ptr = alpn;
	while((*ptr != '\0') && (dest_it < dest_end)) {
		*dest_it = (gnutls_datum_t){
			.data = (unsigned char *)(ptr + 1),
			.size = *ptr
		};
		ptr += (*ptr + 1);
		dest_it++;
	}
	return dest_it - dest;
}

_public_
int knot_quic_set_ecn(const int fd, const int family, const unsigned char ecn,
                      unsigned char *old_ecn)
{
	assert(fd >= 0);
	int opt_level = 0, opt_name = 0;
	switch (family) {
	case AF_INET:
		opt_level = IPPROTO_IP;
		opt_name = IP_TOS;
		break;
	case AF_INET6:
		opt_level = IPPROTO_IPV6;
		opt_name = IPV6_TCLASS;
		break;
	default:
		return KNOT_ENOTSUP;
	}

	if (old_ecn == NULL) {
		if (setsockopt(fd, opt_level, opt_name, &ecn, sizeof(ecn)) == -1) {
			return knot_map_errno();
		}
	} else if (*old_ecn != ecn) {
		if (setsockopt(fd, opt_level, opt_name, &ecn, sizeof(ecn)) == -1) {
			return knot_map_errno();
		}
		*old_ecn = ecn;
	}
	return KNOT_EOK;
}