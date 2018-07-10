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

void php_tomcrypt_xcrypt_ctr(PLTC_CRYPT_PARAM)
{
#ifdef LTC_CTR_MODE
	symmetric_CTR   ctx;
	char           *output, *iv;
	int             err;
	pltc_size       iv_len;
	pltc_long       num_rounds, ctr_mode;

	GET_OPT_STRING(options, "iv", iv, iv_len, NULL);
	GET_OPT_LONG(options, "ctr_mode", ctr_mode, 0);
	GET_OPT_LONG(options, "rounds", num_rounds, 0);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if (iv_len != cipher_descriptor[cipher].block_length) {
		efree(output);
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid iv size (%d), expected %d", iv_len, cipher_descriptor[cipher].block_length);
		RETURN_FALSE;
	}

	if ((err = ctr_start(cipher, iv, key, key_len, num_rounds, ctr_mode, &ctx)) != CRYPT_OK) {
	    goto error;
	}

    if (direction == PLTC_ENCRYPT) {
        err = ctr_encrypt(input, output, input_len, &ctx);
    } else {
        err = ctr_decrypt(input, output, input_len, &ctx);
    }

	if (err != CRYPT_OK) {
		goto error;
	}

	if ((err = ctr_done(&ctx)) != CRYPT_OK) {
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
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported mode");
	RETURN_FALSE;
#endif
}

