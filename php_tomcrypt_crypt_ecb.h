#include <tomcrypt.h>
#include "php_tomcrypt_compat.h"
#include "php_tomcrypt_crypt.h"

static void php_tomcrypt_xcrypt_ecb(PLTC_CRYPT_PARAM)
{
#ifdef LTC_ECB_MODE
	symmetric_ECB  ctx;
	char          *output;
	int            err, num_rounds;

	GET_OPT_LONG(options, "rounds", num_rounds, 0);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if ((err = ecb_start(cipher, key, key_len, num_rounds, &ctx)) != CRYPT_OK) {
		goto error;
	}

	if (direction == PLTC_ENCRYPT) {
		err = ecb_encrypt(input, output, input_len, &ctx);
	} else {
		err = ecb_decrypt(input, output, input_len, &ctx);
	}

	if (err != CRYPT_OK) {
		goto error;
	}

	if ((err = ecb_done(&ctx)) != CRYPT_OK) {
		goto error;
	}
	PLTC_RETURN_STRINGL(output, input_len, 0);

error:
	efree(output);
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
	RETURN_FALSE;
#endif
}

