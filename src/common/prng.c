/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <config.h>
#ifdef HAVE_POSIX_MEMALIGN
#include <stdlib.h>
#endif

#include "libknot/common.h"
#include "common/prng.h"
#include "common/dSFMT.h"

/*! \brief TLS unique key for each thread seed. */
static pthread_key_t tls_prng_key;
static pthread_once_t tls_prng_once = PTHREAD_ONCE_INIT;

static void tls_prng_deinit(void *ptr)
{
	free(ptr);
}

static void tls_prng_deinit_main()
{
	tls_prng_deinit(pthread_getspecific(tls_prng_key));
	UNUSED(pthread_setspecific(tls_prng_key, NULL));
}

static void tls_prng_init()
{
	UNUSED(pthread_key_create(&tls_prng_key, tls_prng_deinit));
	atexit(tls_prng_deinit_main); // Main thread cleanup
}

double tls_rand()
{
	/* Setup PRNG state for current thread. */
	UNUSED(pthread_once(&tls_prng_once, tls_prng_init));

	/* Create PRNG state if not exists. */
	dsfmt_t* s = pthread_getspecific(tls_prng_key);
	if (!s) {
		/* Initialize seed from system PRNG generator. */
		uint32_t seed = 0;
		FILE *fp = fopen("/dev/urandom", "r");
		if (fp == NULL) {
			fp = fopen("/dev/random", "r");
		}
		if (fp != NULL) {
			if (fread(&seed, sizeof(uint32_t), 1, fp) != 1) {
				fclose(fp);
				fp = NULL;
			}
		}
		if (fp == NULL) {
			fprintf(stderr, "error: PRNG: cannot seed from "
				"/dev/urandom, seeding from local time\n");
			struct timeval tv;
			if (gettimeofday(&tv, NULL) == 0) {
				seed = (uint32_t)(tv.tv_sec ^ tv.tv_usec);
			} else {
				/* Last resort. */
				seed = (uint32_t)time(NULL);
			}
		} else {
			fclose(fp);
		}

		/* Initialize PRNG state. */
#ifdef HAVE_POSIX_MEMALIGN
		if (posix_memalign((void **)&s, 16, sizeof(dsfmt_t)) != 0) {
			fprintf(stderr, "error: PRNG: not enough memory\n");
			return .0;
		}
#else
		if ((s = malloc(sizeof(dsfmt_t))) == NULL) {
			fprintf(stderr, "error: PRNG: not enough memory\n");
			return .0;
		}
#endif
		dsfmt_init_gen_rand(s, seed);
		UNUSED(pthread_setspecific(tls_prng_key, s));
	}

	return dsfmt_genrand_close_open(s);
}
