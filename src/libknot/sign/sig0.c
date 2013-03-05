#include <openssl/rsa.h>
#include "common/errcode.h"
#include "sign/key.h"
#include "sign/sig0.h"
#include "sign/bnutils.h"

static int create_rsa_context(const knot_key_params_t *params, void **context)
{
	if (!context)
		return KNOT_EINVAL;

	RSA *rsa = RSA_new();
	if (rsa == NULL)
		return KNOT_ERROR;

	rsa->n    = knot_b64_to_bignum(params->modulus);
	rsa->e    = knot_b64_to_bignum(params->public_exponent);
	rsa->d    = knot_b64_to_bignum(params->private_exponent);
	rsa->p    = knot_b64_to_bignum(params->prime_one);
	rsa->q    = knot_b64_to_bignum(params->prime_two);
	rsa->dmp1 = knot_b64_to_bignum(params->exponent_one);
	rsa->dmq1 = knot_b64_to_bignum(params->exponent_two);
	rsa->iqmp = knot_b64_to_bignum(params->coefficient);

	if (RSA_check_key(rsa) != 1) {
		RSA_free(rsa);
		return KNOT_EINVAL; //! \todo Better error code?
	}

	*context = (void *)rsa;
	return KNOT_EOK;
}

static int free_rsa_context(void *context)
{
	if (!context)
		return KNOT_EINVAL;

	RSA_free((RSA *)context);

	return KNOT_EOK;
}

int knot_dnssec_key_from_params(const knot_key_params_t *params,
				    knot_dnssec_key_t *key)
{
	if (!key || !params)
		return KNOT_EINVAL;

	char *name = strdup(params->name);
	if (!name)
		return KNOT_ENOMEM;

	void *context;
	int result = create_rsa_context(params, &context);
	if (result != KNOT_EOK) {
		free(name);
		return result;
	}

	key->name = name;
	key->algorithm = params->algorithm;
	key->context = context;

	return KNOT_EOK;
}

int knot_dnssec_key_free(knot_dnssec_key_t *key)
{
	if (!key)
		return KNOT_EINVAL;

	if (key->name)
		free(key->name);
	if (key->context)
		free_rsa_context(key->context);

	memset(key, '\0', sizeof(knot_dnssec_key_t));

	return KNOT_EOK;
}
