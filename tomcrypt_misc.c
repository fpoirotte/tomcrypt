/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2017 The PHP Group                                     |
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
#include "php_tomcrypt_compat.h"

ZEND_EXTERN_MODULE_GLOBALS(tomcrypt)

/* {{{ proto void tomcrypt_clear_error()
   Clear the last error returned by LibTomCrypt. */
PHP_FUNCTION(tomcrypt_clear)
{
	TOMCRYPT_G(last_error) = 0;
}
/* }}} */


/* {{{ proto int tomcrypt_errno()
   Retrieve the error number returned by the last LibTomCrypt
   function that failed. */
PHP_FUNCTION(tomcrypt_errno)
{
	RETURN_LONG(TOMCRYPT_G(last_error));
}
/* }}} */


/* {{{ proto string tomcrypt_error(int errno=null)
   Retrieve the error message for the given errno */
PHP_FUNCTION(tomcrypt_error)
{
	pltc_long   err = TOMCRYPT_G(last_error);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &err) == FAILURE) {
		return;
	}

	PLTC_RETVAL_STRING((char *) error_to_string(err), 1);
}
/* }}} */



/* {{{ proto string tomcrypt_hkdf(string algo, string input, int length=0, string salt='', string info='')
   Expand the given input to produce keying material of the desired length */
PHP_FUNCTION(tomcrypt_hkdf)
{
#ifdef LTC_HKDF
    char           *algo, *input, *salt, *info, *output;
    pltc_size       algo_len, input_len, salt_len = 0, info_len = 0;
    pltc_long       output_len = 0;
    int             index, err;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|lss",
		&algo, &algo_len, &input, &input_len, &output_len, &salt, &salt_len, &info, &info_len) == FAILURE) {
		return;
	}

	if ((index = find_hash(algo)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown hashing algorithm: %s", algo);
		RETURN_FALSE;
	}

    if (output_len < 0 || output_len > 255 * hash_descriptor[index].hashsize) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid output length requested (%d)", output_len);
		RETURN_FALSE;
    }

	output = emalloc(output_len + 1);
	output[output_len] = '\0';

    if ((err = hkdf(index, salt, salt_len, info, info_len, input, input_len, output, output_len)) != CRYPT_OK) {
        efree(output);
		TOMCRYPT_G(last_error) = err;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		RETURN_FALSE;
    }

	PLTC_RETURN_STRINGL(output, output_len, 0);
#else
	TOMCRYPT_G(last_error) = CRYPT_ERROR;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported operation");
	RETURN_FALSE;
#endif
}
