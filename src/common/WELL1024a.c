/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>

#include "WELL1024a.h"

#define W 32
#define M1 3
#define M2 24
#define M3 10

#define MAT0POS(t,v) (v^(v>>t))
#define MAT0NEG(t,v) (v^(v<<(-(t))))
#define Identity(v) (v)

#define V0(s)            (s)->state[(s)->i                   ]
#define VM1(s)           (s)->state[((s)->i+M1) & 0x0000001fU]
#define VM2(s)           (s)->state[((s)->i+M2) & 0x0000001fU]
#define VM3(s)           (s)->state[((s)->i+M3) & 0x0000001fU]
#define VRm1(s)          (s)->state[((s)->i+31) & 0x0000001fU]
#define newV0(s)         (s)->state[((s)->i+31) & 0x0000001fU]
#define newV1(s)         (s)->state[(s)->i                   ]

#define FACT 2.32830643653869628906e-10

rngstate_t* InitWELLRNG1024a (unsigned *init) {

	rngstate_t *s = malloc(sizeof(rngstate_t));
	if (s == 0) {
		return 0;
	}

	s->i = 0;
	for (int j = 0; j < WELL1024_WIDTH; j++)
		s->state[j] = init[j];
	return s;
}

double WELLRNG1024a (rngstate_t* s) {
	unsigned z0 = VRm1(s);
	unsigned z1 = Identity(V0(s))       ^ MAT0POS (8, VM1(s));
	unsigned z2 = MAT0NEG (-19, VM2(s)) ^ MAT0NEG(-14,VM3(s));
	newV1(s) = z1                 ^ z2;
	newV0(s) = MAT0NEG (-11,z0)   ^ MAT0NEG(-7,z1)    ^ MAT0NEG(-13,z2) ;
	s->i = (s->i + 31) & 0x0000001fU;
	return ((double) s->state[s->i]  * FACT);
}

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
}

static void tls_prng_init()
{
	(void) pthread_key_create(&tls_prng_key, tls_prng_deinit);
	atexit(tls_prng_deinit_main); // Main thread cleanup
}

double tls_rand()
{
	/* Setup PRNG state for current thread. */
	(void)pthread_once(&tls_prng_once, tls_prng_init);

	/* Create PRNG state if not exists. */
	rngstate_t* s = pthread_getspecific(tls_prng_key);
	if (!s) {
		/* Initialize seed from system PRNG generator. */
		unsigned init[WELL1024_WIDTH];
		FILE *fp = fopen("/dev/urandom", "r");
		if (fp == NULL) {
			fp = fopen("/dev/random", "r");
		}
		if (fp == NULL) {
			fprintf(stderr, "error: PRNG: cannot seed from "
				"/dev/urandom, seeding from local time\n");
			struct timeval tv;
			if (gettimeofday(&tv, NULL) == 0) {
				memcpy(init, &tv, sizeof(struct timeval));
			} else {
				/* Last resort. */
				time_t tm = time(NULL);
				memcpy(init, &tm, sizeof(time_t));
			}
		} else {
			for (unsigned i = 0; i < WELL1024_WIDTH; ++i) {
				int rc = fread(&init[i], sizeof(unsigned), 1, fp);
				rc = rc;
			}
			fclose(fp);
		}

		/* Initialize PRNG state. */
		s = InitWELLRNG1024a(init);
		(void)pthread_setspecific(tls_prng_key, s);
	}

	return WELLRNG1024a(s);
}

void tls_seed_set(unsigned init[WELL1024_WIDTH])
{
	/* Initialize new PRNG state if not exists. */
	rngstate_t* s = pthread_getspecific(tls_prng_key);
	if (!s) {
		s = InitWELLRNG1024a(init);
		(void)pthread_setspecific(tls_prng_key, s);
	} else {
		/* Reset PRNG state if exists. */
		memcpy(s->state, init, sizeof(unsigned) * WELL1024_WIDTH);
		s->i = 0;
	}
}
