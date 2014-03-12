#pragma once

/*!
 * Initialize cryptographic backend.
 */
void dnssec_crypto_init(void);

/*!
 * Reinitialize cryptographic backend.
 *
 * Must be called after fork() by the child.
 */
void dnssec_crypto_reinit(void);

/*!
 * Deinitialize cryptographic backend.
 */
void dnssec_crypto_cleanup(void);
