#include <tomcrypt.h>
#include "php_tomcrypt_compat.h"
#include "php_tomcrypt_crypt.h"

static void php_tomcrypt_xcrypt_xts(PLTC_CRYPT_PARAM)
{
#ifdef LTC_XTS_MODE
	symmetric_xts  ctx;
	char          *output, *key2, *tweak;
	int            err, key2_len, tweak_len, num_rounds;

	GET_OPT_STRING(options, "key2", key2, key2_len, NULL);
	GET_OPT_LONG(options, "rounds", num_rounds, 0);
	GET_OPT_STRING(options, "tweak", tweak, tweak_len, NULL);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if (key2_len != key_len) {
		efree(output);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid length for key2 (%d), expected %d", key2_len, key_len);
		RETURN_FALSE;
	}

	/* XTS uses a fixed-length tweak value. */
	if (tweak_len != 16) {
		efree(output);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid tweak size (%d), expected %d",	tweak_len, 16);
		RETURN_FALSE;
	}

	if ((err = xts_start(cipher, key, key2, key_len, num_rounds, &ctx)) != CRYPT_OK) {
	    goto error;
	}

	/* API inconsistency: input_len & output are swapped compared to other XXX_encrypt() functions. */
    if (direction == PLTC_ENCRYPT) {
        err = xts_encrypt(input, input_len, output, tweak, &ctx);
    } else {
        err = xts_decrypt(input, input_len, output, tweak, &ctx);
    }

	if (err != CRYPT_OK) {
		goto error;
	}

	xts_done(&ctx);
	PLTC_RETURN_STRINGL(output, input_len, 0);

error:
	efree(output);
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
	RETURN_FALSE;
#endif
}

