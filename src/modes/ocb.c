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

void php_tomcrypt_xcrypt_ocb(PLTC_CRYPT_PARAM)
{
#ifdef LTC_OCB_MODE
	char           *output, *nonce, *in_tag, out_tag[MAXBLOCKSIZE + 1];
	int             err, res;
	pltc_size       nonce_len, in_tag_len;
	unsigned long   out_tag_len;

	GET_OPT_STRING(options, "nonce", nonce, nonce_len, NULL);
	GET_OPT_STRING(options, "tag", in_tag, in_tag_len, NULL);

    if (direction == PLTC_ENCRYPT) {
    	GET_OPT_LONG(options, "taglen", out_tag_len, PLTC_DEFAULT_TAG_LENGTH);
    } else {
        out_tag_len = in_tag_len;
    }

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if (nonce_len != cipher_descriptor[cipher].block_length) {
		efree(output);
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid nonce size (%d), expected %d", nonce_len, cipher_descriptor[cipher].block_length);
		RETURN_FALSE;
	}

    if (direction == PLTC_ENCRYPT) {
		if ((err = ocb_encrypt_authenticate_memory(cipher, key, key_len, nonce,
		    input, input_len, output, out_tag, &out_tag_len)) != CRYPT_OK) {
		    efree(output);
			TOMCRYPT_G(last_error) = err;
		    php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		    RETURN_FALSE;
	    }

	    /* Write the tag back. */
	    if (options) {
		    out_tag[out_tag_len] = '\0';
		    pltc_add_assoc_stringl(options, "tag", out_tag, out_tag_len, 1);
	    }
    } else {
        if (in_tag == NULL) {
			efree(output);
		    TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		    php_error_docref(NULL TSRMLS_CC, E_WARNING, "A tag is required when decrypting");
		    RETURN_FALSE;
        }

		if ((err = ocb_decrypt_verify_memory(cipher, key, key_len, nonce,
			input, input_len, output, in_tag, (unsigned long) in_tag_len, &res)) != CRYPT_OK) {
			efree(output);
			TOMCRYPT_G(last_error) = err;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
			RETURN_FALSE;
		}

	    /* Tag verification failed. */
		if (res != 1) {
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

