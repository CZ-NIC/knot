#include "tsig-op.h"
#include "util/error.h"

/*----------------------------------------------------------------------------*/

int knot_tsig_sign(uint8_t *msg, size_t *msg_len, size_t msg_max_len,
                   const uint8_t *request_mac, size_t request_mac_len,
                   const knot_rrset_t *tsig_rr)
{
	return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

int knot_tsig_sign_next(uint8_t *msg, size_t *msg_len, size_t msg_max_len, 
                        const uint8_t *prev_digest, size_t prev_digest_len,
                        const knot_rrset_t *tsig_rr)
{
	return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

int knot_tsig_server_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size)
{
	return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

int knot_tsig_client_check(const knot_rrset_t *tsig_rr,
                           const uint8_t *wire, size_t size,
                           const uint8_t *request_mac, size_t request_mac_len)
{
	return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

int knot_tsig_client_check_next(const knot_rrset_t *tsig_rr,
                                const uint8_t *wire, size_t size,
                                const uint8_t *prev_digest, 
                                size_t prev_digest_len)
{
	return KNOT_ENOTSUP;
}
