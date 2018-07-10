/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2018 The PHP Group                                     |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: François Poirotte <clicky@erebot.net>                        |
  +----------------------------------------------------------------------+
*/

#include <tomcrypt.h>
#include "../compat.h"
#include "crypt_mode.h"

void php_tomcrypt_xcrypt_xts(PLTC_CRYPT_PARAM)
{
#ifdef LTC_XTS_MODE
	symmetric_xts   ctx;
	char           *output, *key2, *tweak;
	int             err;
	pltc_size       key2_len, tweak_len;
	pltc_long       num_rounds;

	GET_OPT_STRING(options, "key2", key2, key2_len, NULL);
	GET_OPT_LONG(options, "rounds", num_rounds, 0);
	GET_OPT_STRING(options, "tweak", tweak, tweak_len, NULL);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if (key2_len != key_len) {
		efree(output);
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid length for key2 (%d), expected %d", key2_len, key_len);
		RETURN_FALSE;
	}

	/* XTS uses a fixed-length tweak value. */
	if (tweak_len != 16) {
		efree(output);
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
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
	TOMCRYPT_G(last_error) = err;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
	RETURN_FALSE;
#else
	TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported mode");
	RETURN_FALSE;
#endif
}

