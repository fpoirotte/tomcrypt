#include <tomcrypt.h>
#include "Zend/zend_types.h"
#include "php_tomcrypt_compat.h"
#include "php_tomcrypt_cipher.h"
#include "php_tomcrypt_crypt.h"

typedef enum {
    /* -1 is reserved (invalid cipher / cipher not found),
       positive values are used for block ciphers. */
    PHP_TOMCRYPT_STREAM_CIPHER_RC4      = -2,
    PHP_TOMCRYPT_STREAM_CIPHER_CHACHA   = -3,
    PHP_TOMCRYPT_STREAM_CIPHER_SOBER128 = -4,
} php_tomcrypt_stream_cipher;


static void php_tomcrypt_xcrypt_stream_chacha(PLTC_CRYPT_PARAM)
{
#ifdef LTC_CHACHA
    chacha_state state;
	char          *output, *nonce;
	int            err, nonce_len, num_rounds;
	pltc_long      counter;

	GET_OPT_STRING(options, "nonce", nonce, nonce_len, NULL);
	GET_OPT_LONG(options, "counter", counter, 0);
	GET_OPT_LONG(options, "rounds", num_rounds, 0);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

    if ((err = chacha_setup(&state, key, key_len, num_rounds)) != CRYPT_OK) {
        goto error;
    }

    if (nonce_len == 12) {
        if ((err = chacha_ivctr32(&state, nonce, nonce_len, counter)) != CRYPT_OK) {
            goto error;
        }
    } else if ((err = chacha_ivctr64(&state, nonce, nonce_len, counter)) != CRYPT_OK) {
        goto error;
    }

    if ((err = chacha_crypt(&state, input, input_len, output)) != CRYPT_OK) {
        goto error;
    }

    if ((err = chacha_done(&state)) != CRYPT_OK) {
        goto error;
    }

	PLTC_RETURN_STRINGL(output, input_len, 0);

error:
	efree(output);
	TOMCRYPT_G(last_error) = err;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
	RETURN_FALSE;
#else
	TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported cipher");
	RETURN_FALSE;
#endif
}


static void php_tomcrypt_xcrypt_stream_rc4(PLTC_CRYPT_PARAM)
{
#ifdef LTC_RC4_STREAM
    rc4_state state;
	char          *output;
	int            err;

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

    if ((err = rc4_stream_setup(&state, key, key_len)) != CRYPT_OK) {
        goto error;
    }

    if ((err = rc4_stream_crypt(&state, input, input_len, output)) != CRYPT_OK) {
        goto error;
    }

    if ((err = rc4_stream_done(&state)) != CRYPT_OK) {
        goto error;
    }

	PLTC_RETURN_STRINGL(output, input_len, 0);

error:
	efree(output);
	TOMCRYPT_G(last_error) = err;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
	RETURN_FALSE;
#else
	TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported cipher");
	RETURN_FALSE;
#endif
}


static void php_tomcrypt_xcrypt_stream_sober128(PLTC_CRYPT_PARAM)
{
#if defined(LTC_SOBER128) && defined(LTC_SOBER128_STREAM)
    sober128_state state;
	char          *output, *nonce;
	int            err, nonce_len;

	GET_OPT_STRING(options, "nonce", nonce, nonce_len, NULL);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

    if ((err = sober128_stream_setup(&state, key, key_len)) != CRYPT_OK) {
        goto error;
    }

    if ((err = sober128_stream_setiv(&state, nonce, nonce_len)) != CRYPT_OK) {
        goto error;
    }

    if ((err = sober128_stream_crypt(&state, input, input_len, output)) != CRYPT_OK) {
        goto error;
    }

    if ((err = sober128_stream_done(&state)) != CRYPT_OK) {
        goto error;
    }

	PLTC_RETURN_STRINGL(output, input_len, 0);

error:
	efree(output);
	TOMCRYPT_G(last_error) = err;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
	RETURN_FALSE;
#else
	TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported cipher");
	RETURN_FALSE;
#endif
}


static void php_tomcrypt_xcrypt_stream(PLTC_CRYPT_PARAM)
{
    typedef void (*stream_xcrypt)(PLTC_CRYPT_PARAM);
    stream_xcrypt funcs[] = {
        php_tomcrypt_xcrypt_stream_chacha,
        php_tomcrypt_xcrypt_stream_rc4,
        php_tomcrypt_xcrypt_stream_sober128,
    };

    /* Map the 1st stream cipher (-2) to 0, the 2nd (-3) to 1, and so on. */
    funcs[(-cipher)-2](PLTC_CRYPT_PARAM_PASSTHRU);
}

