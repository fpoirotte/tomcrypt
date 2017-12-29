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


/* {{{ proto string tomcrypt_error(int errno)
   Retrieve the error message for the given errno */
PHP_FUNCTION(tomcrypt_error)
{
	pltc_long   err;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &err) == FAILURE) {
		return;
	}

	PLTC_RETVAL_STRING((char *) error_to_string(err), 1);
}
/* }}} */

