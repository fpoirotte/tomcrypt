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

#ifndef PHP_TOMCRYPT_CRYPT_H
#define PHP_TOMCRYPT_CRYPT_H

#define PLTC_CRYPT_PARAM          INTERNAL_FUNCTION_PARAMETERS, int cipher, char *key, pltc_size key_len, char *input, pltc_size input_len, zval *options, int direction
#define PLTC_CRYPT_PARAM_PASSTHRU INTERNAL_FUNCTION_PARAM_PASSTHRU, cipher, key, key_len, input, input_len, options, direction

#define PLTC_CRYPT_HANDLER(modconst, handler) \
    extern void handler(PLTC_CRYPT_PARAM); \
	if (!strncmp(modconst, mode, mode_len)) { \
		handler(PLTC_CRYPT_PARAM_PASSTHRU); \
		return; \
	}

/* Carefully crafted values that match LTC_ENCRYPT/LTC_DECRYPT as defined in LibTomCrypt 1.18+. ;)
   Also matches similar constants from previous versions. */
#define PLTC_ENCRYPT 0
#define PLTC_DECRYPT 1

#define PLTC_DEFAULT_TAG_LENGTH 16

typedef enum {
    /* -1 is reserved (invalid cipher / cipher not found),
       positive values are used for block ciphers. */
    PHP_TOMCRYPT_STREAM_CIPHER_RC4      = -2,
    PHP_TOMCRYPT_STREAM_CIPHER_CHACHA   = -3,
    PHP_TOMCRYPT_STREAM_CIPHER_SOBER128 = -4,
} php_tomcrypt_stream_cipher;


#endif /* PHP_TOMCRYPT_CRYPT_H */
