/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <pthread.h>

#include "libknot/common.h"
#include "libknot/dnssec/config.h"
#include "libknot/dnssec/crypto.h"

/*- thread safety -----------------------------------------------------------*/

/*!
 * \brief Mutexes to be used by OpenSSL.
 */
static pthread_mutex_t *openssl_mutex = NULL;
static int openssl_mutex_count = 0;

/*!
 * \brief Callback for OpenSSL mutex locking and unlocking.
 *
 * \see CRYPTO_set_locking_callback() in OpenSSL documentation.
 *
 * \param mode  Locking mode.
 * \param n     Mutex number.
 * \param file  Source file where locking occurs (for debugging).
 * \param line  Line number where locking occurs (for debugging).
 */
static void openssl_mutex_cb(int mode, int n, const char *file, int line)
{
	UNUSED(file);
	UNUSED(line);

	assert(openssl_mutex);
	assert(n < openssl_mutex_count);

	pthread_mutex_t *mutex = &openssl_mutex[n];

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(mutex);
	} else {
		pthread_mutex_unlock(mutex);
	}
}

/*!
 * \brief Initialize mutexes for OpenSSL usage.
 */
static void openssl_mutexes_init(void)
{
	assert(openssl_mutex_count == 0);
	assert(openssl_mutex == NULL);

	openssl_mutex_count = CRYPTO_num_locks();
	if (openssl_mutex_count == 0) {
		return;
	}

	openssl_mutex = calloc(openssl_mutex_count, sizeof(pthread_mutex_t));
	for (int i = 0; i < openssl_mutex_count; i++) {
		pthread_mutex_init(&openssl_mutex[i], NULL);
	}

	CRYPTO_set_locking_callback(openssl_mutex_cb);
}

/*!
 * \brief Destroy mutexes for OpenSSL usage.
 */
static void openssl_mutexes_destroy(void)
{
	assert(openssl_mutex);

	for (int i = 0; i < openssl_mutex_count; i++) {
		pthread_mutex_destroy(&openssl_mutex[i]);
	}

	free(openssl_mutex);

	openssl_mutex_count = 0;
	openssl_mutex = NULL;
}

/*!
 * \brief Callback for thread identification for purpose of OpenSSL.
 *
 * \see CRYPTO_THREADID_set_callback() in OpenSSL documentation.
 *
 * \param openssl_id  Thread identifier in OpenSSL.
 */
static void openssl_threadid_cb(CRYPTO_THREADID *openssl_id)
{
	pthread_t id = pthread_self();
	CRYPTO_THREADID_set_pointer(openssl_id, (void *)id);
}

/*- pluggable engines -------------------------------------------------------*/

#if KNOT_ENABLE_GOST

static ENGINE *gost_engine = NULL;

static void init_gost_engine(void)
{
	assert(gost_engine == NULL);

#ifndef OPENSSL_NO_STATIC_ENGINE
	ENGINE_load_gost();
#else
	ENGINE_load_dynamic();
#endif

	gost_engine = ENGINE_by_id("gost");
	if (!gost_engine) {
		return;
	}

	ENGINE_init(gost_engine);
	ENGINE_register_pkey_asn1_meths(gost_engine);
	ENGINE_ctrl_cmd_string(gost_engine, "CRYPT_PARAMS",
	                       "id-Gost28147-89-CryptoPro-A-ParamSet", 0);
}

static void deinit_gost_engine(void)
{
	assert(gost_engine);

	ENGINE_finish(gost_engine);
	ENGINE_free(gost_engine);

	gost_engine = NULL;
}

#endif

/*- public API --------------------------------------------------------------*/

void knot_crypto_init(void)
{
	OpenSSL_add_all_digests();
}

void knot_crypto_cleanup(void)
{
	knot_crypto_unload_engines();

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	knot_crypto_cleanup_thread();
}

void knot_crypto_cleanup_thread(void)
{
	ERR_remove_state(0);
}

void knot_crypto_init_threads(void)
{
	// locking
	if (!openssl_mutex) {
		openssl_mutexes_init();
	}

	// thread identification
	CRYPTO_THREADID_set_callback(openssl_threadid_cb);
}

void knot_crypto_cleanup_threads(void)
{
	if (openssl_mutex) {
		openssl_mutexes_destroy();
	}
}

void knot_crypto_load_engines(void)
{
#if KNOT_ENABLE_GOST
	if (!gost_engine) {
		init_gost_engine();
	}
#endif
}

void knot_crypto_unload_engines(void)
{
#if KNOT_ENABLE_GOST
	if (gost_engine) {
		deinit_gost_engine();
	}
#endif
}
