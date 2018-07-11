/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2015 The PHP Group                                     |
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "SAPI.h"
#include "Zend/zend_types.h"
#include "ext/standard/html.h"
#include "ext/standard/info.h"

#if HAVE_LIBTOMCRYPT

#include <tomcrypt.h>
#include "php_tomcrypt.h"
#include "compat.h"
#include "rng.h"
#include "cipher.h"
#include "hash.h"
#include "mac.h"
#include "mode.h"

ZEND_DECLARE_MODULE_GLOBALS(tomcrypt)
static PHP_GINIT_FUNCTION(tomcrypt);

/* {{{ arginfo */

/* Misc. */
PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_clear, 0, 0, IS_NULL, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_errno, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_error, 0, 0, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, errno, IS_LONG, 1)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_hkdf, 0, 2, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, algo, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, input, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, salt, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, info, IS_STRING, 0)
ZEND_END_ARG_INFO()


/* Lists */
PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_list_modes, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_list_ciphers, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_list_hashes, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_list_macs, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_list_rngs, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()


/* Ciphers */
PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_cipher_block_size, 0, 1, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, cipher, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_cipher_adapt_key_size, 0, 2, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, cipher, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, keysize, IS_LONG, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_cipher_min_key_size, 0, 1, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, cipher, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_cipher_max_key_size, 0, 1, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, cipher, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_cipher_default_rounds, 0, 1, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, cipher, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_cipher_encrypt, 0, 4, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, cipher, IS_STRING, 1) /* Optional for modes like ChaCha20 */
	PLTC_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, plaintext, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, mode, IS_STRING, 0)
	ZEND_ARG_ARRAY_INFO(0, options, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_cipher_decrypt, 0, 4, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, cipher, IS_STRING, 1) /* Optional for modes like ChaCha20 */
	PLTC_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, mode, IS_STRING, 0)
	ZEND_ARG_ARRAY_INFO(0, options, 0)
ZEND_END_ARG_INFO()


/* Hashes */
PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_hash_block_size, 0, 1, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, algo, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_hash_digest_size, 0, 1, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, algo, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_hash_string, 0, 2, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, algo, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, raw_output, IS_BOOL, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_hash_file, 0, 2, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, algo, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, filename, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, raw_output, IS_BOOL, 0)
ZEND_END_ARG_INFO()


/* MAC */
PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_mac_string, 0, 4, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, algo, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, cipher_hash, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, raw_output, IS_BOOL, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_mac_file, 0, 4, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, algo, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, cipher_hash, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, key, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, filename, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, raw_output, IS_BOOL, 0)
ZEND_END_ARG_INFO()


/* PRNGs */
PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_rng_get_bytes, 0, 1, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, size, IS_LONG, 0)
	PLTC_ARG_TYPE_INFO(0, prng, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_rng_import, 0, 2, IS_BOOL, 0)
	PLTC_ARG_TYPE_INFO(0, prng, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, state, IS_STRING, 0)
ZEND_END_ARG_INFO()

PLTC_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_tomcrypt_rng_export, 0, 1, IS_STRING, 0)
	PLTC_ARG_TYPE_INFO(0, prng, IS_STRING, 0)
ZEND_END_ARG_INFO()

/* }}} */

const zend_function_entry tomcrypt_functions[] = { /* {{{ */
	/* Misc. */
	PHP_FE(tomcrypt_clear,					arginfo_tomcrypt_clear)
	PHP_FE(tomcrypt_errno,					arginfo_tomcrypt_errno)
	PHP_FE(tomcrypt_error,					arginfo_tomcrypt_error)
	PHP_FE(tomcrypt_hkdf,					arginfo_tomcrypt_hkdf)

	/* Lists */
	PHP_FE(tomcrypt_list_modes,				arginfo_tomcrypt_list_modes)
	PHP_FE(tomcrypt_list_ciphers,			arginfo_tomcrypt_list_ciphers)
	PHP_FE(tomcrypt_list_hashes,			arginfo_tomcrypt_list_hashes)
	PHP_FE(tomcrypt_list_macs,				arginfo_tomcrypt_list_macs)
	PHP_FE(tomcrypt_list_rngs,				arginfo_tomcrypt_list_rngs)

	/* Ciphers */
	PHP_FE(tomcrypt_cipher_block_size,		arginfo_tomcrypt_cipher_block_size)
	PHP_FE(tomcrypt_cipher_adapt_key_size,	arginfo_tomcrypt_cipher_adapt_key_size)
	PHP_FE(tomcrypt_cipher_min_key_size,	arginfo_tomcrypt_cipher_min_key_size)
	PHP_FE(tomcrypt_cipher_max_key_size,	arginfo_tomcrypt_cipher_max_key_size)
	PHP_FE(tomcrypt_cipher_default_rounds,	arginfo_tomcrypt_cipher_default_rounds)
	PHP_FE(tomcrypt_cipher_encrypt,			arginfo_tomcrypt_cipher_encrypt)
	PHP_FE(tomcrypt_cipher_decrypt,			arginfo_tomcrypt_cipher_decrypt)

	/* Hashes */
	PHP_FE(tomcrypt_hash_block_size,		arginfo_tomcrypt_hash_block_size)
	PHP_FE(tomcrypt_hash_digest_size,		arginfo_tomcrypt_hash_digest_size)
	PHP_FE(tomcrypt_hash_string,			arginfo_tomcrypt_hash_string)
	PHP_FE(tomcrypt_hash_file,				arginfo_tomcrypt_hash_file)

	/* MAC */
	PHP_FE(tomcrypt_mac_string,				arginfo_tomcrypt_mac_string)
	PHP_FE(tomcrypt_mac_file,				arginfo_tomcrypt_mac_file)

	/* PRNGs */
	PHP_FE(tomcrypt_rng_get_bytes, 			arginfo_tomcrypt_rng_get_bytes)
	PHP_FE(tomcrypt_rng_import, 			arginfo_tomcrypt_rng_import)
	PHP_FE(tomcrypt_rng_export, 			arginfo_tomcrypt_rng_export)

	PHP_FE_END
};
/* }}} */

static PHP_MINFO_FUNCTION(tomcrypt);
static PHP_MINIT_FUNCTION(tomcrypt);
static PHP_MSHUTDOWN_FUNCTION(tomcrypt);

zend_module_entry tomcrypt_module_entry = {
	STANDARD_MODULE_HEADER,
	"tomcrypt",
	tomcrypt_functions,
	PHP_MINIT(tomcrypt),
	PHP_MSHUTDOWN(tomcrypt),
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	PHP_MINFO(tomcrypt),
	PHP_TOMCRYPT_VERSION,
	PHP_MODULE_GLOBALS(tomcrypt),
	PHP_GINIT(tomcrypt),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_TOMCRYPT
ZEND_GET_MODULE(tomcrypt)
#endif

/* {{{ */
static PHP_GINIT_FUNCTION(tomcrypt)
{
        tomcrypt_globals->last_error = CRYPT_OK;
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
static PHP_MINIT_FUNCTION(tomcrypt)
{
	REGISTER_LONG_CONSTANT("LIBTOMCRYPT_VERSION_NUMBER", CRYPT, CONST_PERSISTENT | CONST_CS);
	REGISTER_STRING_CONSTANT("LIBTOMCRYPT_VERSION_TEXT", SCRYPT, CONST_PERSISTENT | CONST_CS);
	REGISTER_STRING_CONSTANT("TOMCRYPT_VERSION", PHP_TOMCRYPT_VERSION, CONST_PERSISTENT | CONST_CS);
	REGISTER_STRING_CONSTANT("TOMCRYPT_API_VERSION", PHP_TOMCRYPT_API_VERSION, CONST_PERSISTENT | CONST_CS);

    /* Expose whether LTC was compiled in fast mode or not. */
#ifdef LTC_FAST
	REGISTER_BOOL_CONSTANT("TOMCRYPT_FAST", 1, CONST_PERSISTENT | CONST_CS);
#else
	REGISTER_BOOL_CONSTANT("TOMCRYPT_FAST", 0, CONST_PERSISTENT | CONST_CS);
#endif

    /* Initialize the various components.
       PRNGs must be initialized last due to dependencies. */
	if (init_ciphers(module_number TSRMLS_CC) != 0 ||
		init_hashes(module_number TSRMLS_CC) != 0 ||
		init_macs(module_number TSRMLS_CC) != 0 ||
		init_modes(module_number TSRMLS_CC) != 0 ||
		init_prngs(module_number TSRMLS_CC) != 0) {
		return FAILURE;
	}

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
static PHP_MSHUTDOWN_FUNCTION(tomcrypt)
{
	return deinit_prngs() ? FAILURE : SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
static PHP_MINFO_FUNCTION(tomcrypt)
{
	char *cr, *lf;
	const char *end, *start = crypt_build_settings;

	php_info_print_table_start();
	php_info_print_table_header(2, "libtomcrypt support", "enabled");
	php_info_print_table_row(2, "extension version", PHP_TOMCRYPT_VERSION);
	php_info_print_table_row(2, "extension API version", PHP_TOMCRYPT_API_VERSION);
	php_info_print_table_row(2, "library version", SCRYPT);
	php_info_print_table_end();

	php_info_print_box_start(0);
	while (start != NULL && *start) {
		cr = strchr(start, '\r');
		lf = strchr(start, '\n');

		if (cr == NULL) {
			end = lf;
		} else if (lf == NULL) {
			end = cr;
		} else {
			end = (cr < lf) ? cr : lf;
		}

		if (end == NULL)
			end = strchr(start, '\0');

		if (!sapi_module.phpinfo_as_text) {
#if (PHP_VERSION_ID >= 70000)
			zend_string *new_str;

			new_str = php_escape_html_entities((unsigned char *) start, end - start, 0, ENT_QUOTES, "utf-8" TSRMLS_CC);
			php_output_write(ZSTR_VAL(new_str), ZSTR_LEN(new_str));
			zend_string_free(new_str);
#else
#if (PHP_VERSION_ID < 50400)
			int new_len;
#else
			size_t new_len;
#endif
			char *new_str;

			new_str = php_escape_html_entities((unsigned char *) start, end - start, &new_len, 0, ENT_QUOTES, "utf-8" TSRMLS_CC);
			php_output_write(new_str, new_len TSRMLS_CC);
			str_efree(new_str);
#endif
		} else {
			php_output_write(start, end - start TSRMLS_CC);
		}

		if (!*end)
			break;

        PUTS(!sapi_module.phpinfo_as_text ?"<br />" : "\n");

		start = end + 1;
		if ((*start == '\r' || *start == '\n') && *start != *(start-1)) {
			start++;
		}
	}
	php_info_print_box_end();
}
/* }}} */


#endif /* HAVE_LIBTOMCRYPT */
