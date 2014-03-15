#include <stdint.h>

#include "binary.h"

/*!
 * Compute keytag for a DNSSEC key.
 *
 * \param[in]  rdata   DNSKEY RDATA.
 * \param[out] keytag  Computed keytag.
 *
 * \return Error code, DNSSEC_EOK of successful.
 */
int keytag(const dnssec_binary_t *rdata, uint16_t *keytag);
