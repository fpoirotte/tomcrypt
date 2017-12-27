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
#include "php_tomcrypt_rng.h"

#ifdef LTC_CHACHA20_PRNG
#define PHP_TOMCRYPT_DESC_PRNG_CHACHA20 &chacha20_prng_desc
#else
#define PHP_TOMCRYPT_DESC_PRNG_CHACHA20 NULL
#endif

#ifdef LTC_FORTUNA
#define PHP_TOMCRYPT_DESC_PRNG_FORTUNA &fortuna_desc
#else
#define PHP_TOMCRYPT_DESC_PRNG_FORTUNA NULL
#endif

#ifdef LTC_RC4
#define PHP_TOMCRYPT_DESC_PRNG_RC4 &rc4_desc
#else
#define PHP_TOMCRYPT_DESC_PRNG_RC4 NULL
#endif

#ifdef LTC_SPRNG
#define PHP_TOMCRYPT_DESC_PRNG_SECURE &sprng_desc
#else
#define PHP_TOMCRYPT_DESC_PRNG_SECURE NULL
#endif

#ifdef LTC_SOBER128
#define PHP_TOMCRYPT_DESC_PRNG_SOBER128 &sober128_desc
#else
#define PHP_TOMCRYPT_DESC_PRNG_SOBER128 NULL
#endif

#ifdef LTC_YARROW
#define PHP_TOMCRYPT_DESC_PRNG_YARROW &yarrow_desc
#else
#define PHP_TOMCRYPT_DESC_PRNG_YARROW NULL
#endif


#define TOMCRYPT_DEFINE_RNG(rng) { \
	.php_const = "TOMCRYPT_RNG_" # rng, \
	.php_value = PHP_TOMCRYPT_RNG_ ## rng, \
	.desc = PHP_TOMCRYPT_DESC_PRNG_ ## rng \
}

static struct {
	const char                         *php_const;
	const char                         *php_value;
	const struct ltc_prng_descriptor   *desc;
	prng_state                          state;
} php_tomcrypt_rngs[] = {
	TOMCRYPT_DEFINE_RNG(CHACHA20),
	TOMCRYPT_DEFINE_RNG(FORTUNA),
	TOMCRYPT_DEFINE_RNG(RC4),
	TOMCRYPT_DEFINE_RNG(SECURE),
	TOMCRYPT_DEFINE_RNG(SOBER128),
	TOMCRYPT_DEFINE_RNG(YARROW),
	{ NULL }
};

int init_prngs(int module_number TSRMLS_DC)
{
	unsigned short i;

	for (i = 0; php_tomcrypt_rngs[i].php_const != NULL; i++) {
		zend_register_string_constant(php_tomcrypt_rngs[i].php_const, strlen(php_tomcrypt_rngs[i].php_const),
			(char *) php_tomcrypt_rngs[i].php_value, CONST_PERSISTENT | CONST_CS, module_number TSRMLS_CC);

		if (php_tomcrypt_rngs[i].desc == NULL) {
			continue;
		}

		if (register_prng(php_tomcrypt_rngs[i].desc) == -1 ||
			rng_make_prng(128, find_prng(php_tomcrypt_rngs[i].desc->name), &php_tomcrypt_rngs[i].state, NULL) == -1) {
			return -1;
		}
	}
	return 0;
}

int deinit_prngs(void)
{
	unsigned short i;

	for (i = 0; php_tomcrypt_rngs[i].php_const != NULL; i++) {
		if (php_tomcrypt_rngs[i].desc != NULL) {
			php_tomcrypt_rngs[i].desc->done(&php_tomcrypt_rngs[i].state);
		}
	}
	return 0;
}

/* {{{ proto array tomcrypt_list_rngs()
   List all available (Pseudo-)Random Number Generators (PRNGs) */
PHP_FUNCTION(tomcrypt_list_rngs)
{
	int i, j = 0;
	array_init(return_value);
	for (i = 0; php_tomcrypt_rngs[i].php_const != NULL; i++) {
		if (php_tomcrypt_rngs[i].desc != NULL) {
			pltc_add_index_string(return_value, j++, php_tomcrypt_rngs[i].php_value, 1);
		}
	}
}
/* }}} */

/* {{{ proto string tomcrypt_rng_get_bytes(int size, string rng = TOMCRYPT_RNG_SECURE)
   Get some random bytes from the (Pseudo-)RNG */
PHP_FUNCTION(tomcrypt_rng_get_bytes)
{
	char           sprng[] = PHP_TOMCRYPT_RNG_SECURE;
	char          *rng = sprng;
	pltc_size      rng_len = sizeof(PHP_TOMCRYPT_RNG_SECURE);
	int            i;
	pltc_long      size;
	unsigned char *buffer;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|s", &size, &rng, &rng_len) == FAILURE) {
		return;
	}

	if (size <= 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid size (%s)", size);
		RETURN_FALSE;
	}

	for (i = 0; php_tomcrypt_rngs[i].php_const != NULL; i++) {
		if (!strncmp(php_tomcrypt_rngs[i].php_value, rng, rng_len) &&
			php_tomcrypt_rngs[i].desc != NULL) {

			if (php_tomcrypt_rngs[i].desc->ready(&php_tomcrypt_rngs[i].state) != CRYPT_OK) {
				RETURN_FALSE;
			}

			buffer = emalloc(size + 1);
			size = (int) php_tomcrypt_rngs[i].desc->read(buffer, size, &php_tomcrypt_rngs[i].state);
			buffer[size] = '\0';
			PLTC_RETVAL_STRINGL(buffer, size, 0);
			return;
		}
	}

	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown RNG: %s", rng);
	RETURN_FALSE;
}
/* }}} */

