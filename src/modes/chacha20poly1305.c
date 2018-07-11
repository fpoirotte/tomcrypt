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

void php_tomcrypt_xcrypt_chacha20poly1305(PLTC_CRYPT_PARAM)
{
#ifdef LTC_CHACHA20POLY1305_MODE
	char           *output, *iv, *authdata, *in_tag, out_tag[MAXBLOCKSIZE + 1];
	pltc_size       iv_len, authdata_len, in_tag_len;
	int             err;
	unsigned long   out_tag_len;

	GET_OPT_STRING(options, "iv", iv, iv_len, NULL);
	GET_OPT_STRING(options, "authdata", authdata, authdata_len, NULL);
	GET_OPT_STRING(options, "tag", in_tag, in_tag_len, NULL);

    if (direction == PLTC_ENCRYPT) {
    	GET_OPT_LONG(options, "taglen", out_tag_len, PLTC_DEFAULT_TAG_LENGTH);
    } else {
        out_tag_len = in_tag_len;
    }

    if (key_len != 16 && key_len != 32) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid key length (expected 16 or 32 bytes)");
		RETURN_FALSE;
    }

    if (out_tag_len < 16 || out_tag_len > MAXBLOCKSIZE) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid tag length (should be between 16 and %d)", MAXBLOCKSIZE);
		RETURN_FALSE;
    }

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if ((err = chacha20poly1305_memory(key, key_len, iv, iv_len, authdata, authdata_len,
		input, input_len, output, out_tag, &out_tag_len, direction)) != CRYPT_OK) {
		efree(output);
		TOMCRYPT_G(last_error) = err;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		RETURN_FALSE;
	}

    if (direction == PLTC_ENCRYPT) {
	    if (options) {
	        /* Write the tag back into the options. */
		    out_tag[out_tag_len] = '\0';
		    pltc_add_assoc_stringl(options, "tag", out_tag, out_tag_len, 1);
	    }
    } else {
		if (in_tag_len != out_tag_len || memcmp(out_tag, in_tag, out_tag_len)) {
			efree(output);
			TOMCRYPT_G(last_error) = CRYPT_ERROR;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Tag verification failed");
			RETURN_FALSE;
		}
    }

	PLTC_RETURN_STRINGL(output, input_len, 0);
#else
	TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported mode");
	RETURN_FALSE;
#endif
}

