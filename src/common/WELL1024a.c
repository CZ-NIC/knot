/* ***************************************************************************** */
/* Copyright:      Francois Panneton and Pierre L'Ecuyer, University of Montreal */
/*                 Makoto Matsumoto, Hiroshima University                        */
/* Notice:         This code can be used freely for personal, academic,          */
/*                 or non-commercial purposes. For commercial purposes,          */
/*                 please contact P. L'Ecuyer at: lecuyer@iro.UMontreal.ca       */
/* ***************************************************************************** */

#define W 32
#define R 32
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

typedef struct {
	unsigned i;
	unsigned state[R]; /* 128 bits */
} rngstate_t;

rngstate_t* InitWELLRNG1024a (unsigned *init) {

	rngstate_t *s = malloc(sizeof(rngstate_t));
	if (s == 0) {
		return 0;
	}

	s->i = 0;
	for (int j = 0; j < R; j++)
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
