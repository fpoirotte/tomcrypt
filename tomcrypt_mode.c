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
#include "php_tomcrypt_mode.h"

#ifdef LTC_CBC_MODE
#define PHP_TOMCRYPT_DESC_MODE_CBC 1
#else
#define PHP_TOMCRYPT_DESC_MODE_CBC 0
#endif

#ifdef LTC_CCM_MODE
#define PHP_TOMCRYPT_DESC_MODE_CCM 1
#else
#define PHP_TOMCRYPT_DESC_MODE_CCM 0
#endif

#ifdef LTC_CFB_MODE
#define PHP_TOMCRYPT_DESC_MODE_CFB 1
#else
#define PHP_TOMCRYPT_DESC_MODE_CFB 0
#endif

#ifdef LTC_CHACHA20POLY1305_MODE
#define PHP_TOMCRYPT_DESC_MODE_CHACHA20POLY1305 1
#else
#define PHP_TOMCRYPT_DESC_MODE_CHACHA20POLY1305 0
#endif

#ifdef LTC_CTR_MODE
#define PHP_TOMCRYPT_DESC_MODE_CTR 1
#else
#define PHP_TOMCRYPT_DESC_MODE_CTR 0
#endif

#ifdef LTC_EAX_MODE
#define PHP_TOMCRYPT_DESC_MODE_EAX 1
#else
#define PHP_TOMCRYPT_DESC_MODE_EAX 0
#endif

#ifdef LTC_ECB_MODE
#define PHP_TOMCRYPT_DESC_MODE_ECB 1
#else
#define PHP_TOMCRYPT_DESC_MODE_ECB 0
#endif

#ifdef LTC_F8_MODE
#define PHP_TOMCRYPT_DESC_MODE_F8 1
#else
#define PHP_TOMCRYPT_DESC_MODE_F8 0
#endif

#ifdef LTC_GCM_MODE
#define PHP_TOMCRYPT_DESC_MODE_GCM 1
#else
#define PHP_TOMCRYPT_DESC_MODE_GCM 0
#endif

#ifdef LTC_LRW_MODE
#define PHP_TOMCRYPT_DESC_MODE_LRW 1
#else
#define PHP_TOMCRYPT_DESC_MODE_LRW 0
#endif

#ifdef LTC_OCB_MODE
#define PHP_TOMCRYPT_DESC_MODE_OCB 1
#else
#define PHP_TOMCRYPT_DESC_MODE_OCB 0
#endif

#ifdef LTC_OCB3_MODE
#define PHP_TOMCRYPT_DESC_MODE_OCB3 1
#else
#define PHP_TOMCRYPT_DESC_MODE_OCB3 0
#endif

#ifdef LTC_OFB_MODE
#define PHP_TOMCRYPT_DESC_MODE_OFB 1
#else
#define PHP_TOMCRYPT_DESC_MODE_OFB 0
#endif

#ifdef LTC_XTS_MODE
#define PHP_TOMCRYPT_DESC_MODE_XTS 1
#else
#define PHP_TOMCRYPT_DESC_MODE_XTS 0
#endif

/* Hack to support stream ciphers */
#define PHP_TOMCRYPT_DESC_MODE_STREAM 1

#define TOMCRYPT_DEFINE_MODE(mode) { \
	.php_const = "TOMCRYPT_MODE_" # mode, \
	.php_value = PHP_TOMCRYPT_MODE_ ## mode, \
	.present = PHP_TOMCRYPT_DESC_MODE_ ## mode \
}

static struct {
	const char     *php_const;
	const char     *php_value;
	unsigned char   present;
} php_tomcrypt_modes[] = {
	TOMCRYPT_DEFINE_MODE(CBC),
	TOMCRYPT_DEFINE_MODE(CCM),
	TOMCRYPT_DEFINE_MODE(CFB),
	TOMCRYPT_DEFINE_MODE(CTR),
	TOMCRYPT_DEFINE_MODE(CHACHA20POLY1305),
	TOMCRYPT_DEFINE_MODE(EAX),
	TOMCRYPT_DEFINE_MODE(ECB),
	TOMCRYPT_DEFINE_MODE(F8),
	TOMCRYPT_DEFINE_MODE(GCM),
	TOMCRYPT_DEFINE_MODE(LRW),
	TOMCRYPT_DEFINE_MODE(OCB),
	TOMCRYPT_DEFINE_MODE(OCB3),
	TOMCRYPT_DEFINE_MODE(OFB),
	TOMCRYPT_DEFINE_MODE(STREAM),
	TOMCRYPT_DEFINE_MODE(XTS),
	{ NULL }
};

int init_modes(int module_number TSRMLS_DC)
{
	int i;

	for (i = 0; php_tomcrypt_modes[i].php_const != NULL; i++) {
	    PLTC_REGISTER_STRING_CONSTANT(php_tomcrypt_modes[i].php_const,
	        (char *) php_tomcrypt_modes[i].php_value, CONST_PERSISTENT | CONST_CS);
	}

	/* Values taken from tomcrypt_cipher.h.
	   For consistency, we always define these values, even when
	   LibTomCrypt was compiled without support for the CTR mode. */
	REGISTER_LONG_CONSTANT("TOMCRYPT_CTR_LITTLE_ENDIAN", 0x0000, CONST_PERSISTENT | CONST_CS);
	REGISTER_LONG_CONSTANT("TOMCRYPT_CTR_BIG_ENDIAN", 0x1000, CONST_PERSISTENT | CONST_CS);
	REGISTER_LONG_CONSTANT("TOMCRYPT_CTR_RFC3686", 0x2000, CONST_PERSISTENT | CONST_CS);
	return 0;
}

/* {{{ proto array tomcrypt_list_modes()
   List all available cipher modes */
PHP_FUNCTION(tomcrypt_list_modes)
{
	int i, j = 0;
	array_init(return_value);
	for (i = 0; php_tomcrypt_modes[i].php_const != NULL; i++) {
		if (php_tomcrypt_modes[i].present == 1) {
			pltc_add_index_string(return_value, j++, php_tomcrypt_modes[i].php_value, 1);
		}
	}
}
/* }}} */

