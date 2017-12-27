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
#include "php_tomcrypt_mac.h"
#include "php_tomcrypt_utils.h"

#define TOMCRYPT_DEFINE_MAC(mac) \
	REGISTER_STRING_CONSTANT("TOMCRYPT_MAC_" #mac, PHP_TOMCRYPT_MAC_ ##mac , CONST_PERSISTENT | CONST_CS)


/* Wrappers to keep the API consistent across all MAC algorithms. */
#ifdef LTC_BLAKE2BMAC
static int php_tomcrypt_blake2bmac_init(blake2bmac_state *state, int algo, const unsigned char *key, unsigned long keylen)
{
    return blake2bmac_init(state, 64, key, keylen); /* 64-byte long MAC. */
}
#endif
#ifdef LTC_BLAKE2SMAC
static int php_tomcrypt_blake2smac_init(blake2smac_state *state, int algo, const unsigned char *key, unsigned long keylen)
{
    return blake2smac_init(state, 64, key, keylen); /* 64-byte long MAC. */
}
#endif
#ifdef LTC_POLY1305
static int php_tomcrypt_poly1305_init(poly1305_state *state, int algo, const unsigned char *key, unsigned long keylen)
{
    return poly1305_init(state, key, keylen);
}
#endif

typedef union {
#ifdef LTC_HMAC
	hmac_state          hmac;
#endif
#ifdef LTC_BLAKE2BMAC
	blake2bmac_state    blake2b;
#endif
#ifdef LTC_BLAKE2SMAC
	blake2smac_state    blake2s;
#endif
#ifdef LTC_PMAC
	pmac_state          pmac;
#endif
#ifdef LTC_PELICAN
	pelican_state       pelican;
#endif
#ifdef LTC_POLY1305
	poly1305_state      poly1305;
#endif
#ifdef LTC_XCBC
	xcbc_state          xcbc;
#endif
#ifdef LTC_F9_MODE
	f9_state            f9;
#endif
} php_tomcrypt_mac_state;


typedef int (*php_tomcrypt_mac_find)(const char *name);
typedef int (*php_tomcrypt_mac_init)(void *state, int algo, const unsigned char *key, unsigned long keylen);
typedef int (*php_tomcrypt_mac_process)(void *state, const unsigned char *in, unsigned long inlen);
typedef int (*php_tomcrypt_mac_done)(void *state, unsigned char *out, unsigned long *outlen);

static struct {
	char                       *name;
	php_tomcrypt_mac_find       find;
	php_tomcrypt_mac_init       init;
	php_tomcrypt_mac_process    process;
	php_tomcrypt_mac_done       done;
} php_tomcrypt_mac_descriptors[] = {
#ifdef LTC_BLAKE2BMAC
	{
		PHP_TOMCRYPT_MAC_BLAKE2B,
		(php_tomcrypt_mac_find)    NULL,
		(php_tomcrypt_mac_init)    php_tomcrypt_blake2bmac_init,
		(php_tomcrypt_mac_process) blake2bmac_process,
		(php_tomcrypt_mac_done)    blake2bmac_done
	},
#endif
#ifdef LTC_BLAKE2SMAC
	{
		PHP_TOMCRYPT_MAC_BLAKE2S,
		(php_tomcrypt_mac_find)    NULL,
		(php_tomcrypt_mac_init)    php_tomcrypt_blake2smac_init,
		(php_tomcrypt_mac_process) blake2smac_process,
		(php_tomcrypt_mac_done)    blake2smac_done
	},
#endif
#ifdef LTC_OMAC
	{
		PHP_TOMCRYPT_MAC_CMAC,
		(php_tomcrypt_mac_find)    find_cipher,
		(php_tomcrypt_mac_init)    omac_init,
		(php_tomcrypt_mac_process) omac_process,
		(php_tomcrypt_mac_done)    omac_done
	},
#endif
#ifdef LTC_F9_MODE
	{
		PHP_TOMCRYPT_MAC_F9,
		(php_tomcrypt_mac_find)    find_cipher,
		(php_tomcrypt_mac_init)    f9_init,
		(php_tomcrypt_mac_process) f9_process,
		(php_tomcrypt_mac_done)    f9_done
	},
#endif
#ifdef LTC_HMAC
	{
		PHP_TOMCRYPT_MAC_HMAC,
		(php_tomcrypt_mac_find)    find_hash,
		(php_tomcrypt_mac_init)    hmac_init,
		(php_tomcrypt_mac_process) hmac_process,
		(php_tomcrypt_mac_done)    hmac_done
	},
#endif
#ifdef LTC_PELICAN
	{
		PHP_TOMCRYPT_MAC_PELICAN,
		(php_tomcrypt_mac_find)    find_cipher,
		(php_tomcrypt_mac_init)    pelican_init,
		(php_tomcrypt_mac_process) pelican_process,
		(php_tomcrypt_mac_done)    pelican_done
	},
#endif
#ifdef LTC_PMAC
	{
		PHP_TOMCRYPT_MAC_PMAC,
		(php_tomcrypt_mac_find)    find_cipher,
		(php_tomcrypt_mac_init)    pmac_init,
		(php_tomcrypt_mac_process) pmac_process,
		(php_tomcrypt_mac_done)    pmac_done
	},
#endif
#ifdef LTC_POLY1305
	{
		PHP_TOMCRYPT_MAC_POLY1305,
		(php_tomcrypt_mac_find)    NULL,
		(php_tomcrypt_mac_init)    php_tomcrypt_poly1305_init,
		(php_tomcrypt_mac_process) poly1305_process,
		(php_tomcrypt_mac_done)    poly1305_done
	},
#endif
#ifdef LTC_XCBC
	{
		PHP_TOMCRYPT_MAC_XCBC,
		(php_tomcrypt_mac_find)    find_cipher,
		(php_tomcrypt_mac_init)    xcbc_init,
		(php_tomcrypt_mac_process) xcbc_process,
		(php_tomcrypt_mac_done)    xcbc_done
	},
#endif
	{NULL}
};


int init_macs(int module_number TSRMLS_DC)
{
	TOMCRYPT_DEFINE_MAC(BLAKE2B);
	TOMCRYPT_DEFINE_MAC(BLAKE2S);
	TOMCRYPT_DEFINE_MAC(CMAC);
	TOMCRYPT_DEFINE_MAC(F9);
	TOMCRYPT_DEFINE_MAC(HMAC);
	TOMCRYPT_DEFINE_MAC(PELICAN);
	TOMCRYPT_DEFINE_MAC(PMAC);
	TOMCRYPT_DEFINE_MAC(POLY1305);
	TOMCRYPT_DEFINE_MAC(XCBC);
	return 0;
}

/* {{{ proto array tomcrypt_list_macs()
   List all available MAC protocols */
PHP_FUNCTION(tomcrypt_list_macs)
{
	int   i = 0;

	array_init(return_value);
	for (i = 0; php_tomcrypt_mac_descriptors[i].done != NULL; i++) {
		pltc_add_index_string(return_value, i, php_tomcrypt_mac_descriptors[i].name, 1);
	}
}
/* }}} */

static void php_tomcrypt_do_mac(INTERNAL_FUNCTION_PARAMETERS, int isfilename)
/* {{{ */
{
	char                   *algo, *cipher_hash, *key, *data, mac[MAXBLOCKSIZE + 1];
	unsigned long           macsize = MAXBLOCKSIZE;
	pltc_size               algo_len, cipher_hash_len, key_len, data_len;
	int                     err, index = -1, i;
	zend_bool               raw_output = 0;
	php_stream             *stream = NULL;
	php_tomcrypt_mac_state  state;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss|b",
		&algo, &algo_len, &cipher_hash, &cipher_hash_len,
		&key, &key_len, &data, &data_len, &raw_output) == FAILURE) {
		return;
	}

	for (i = 0; php_tomcrypt_mac_descriptors[i].name != NULL; i++) {
		if (!strcasecmp(php_tomcrypt_mac_descriptors[i].name, algo)) {
			break;
		}
	}

	if (index == -1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown MAC algorithm: %s", algo);
		RETURN_FALSE;
	}

	if (php_tomcrypt_mac_descriptors[index].find != NULL &&
	    (i = php_tomcrypt_mac_descriptors[index].find(cipher_hash)) == -1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher/hash: %s", cipher_hash);
		RETURN_FALSE;
	}

	if ((err = php_tomcrypt_mac_descriptors[index].init(&state, i, key, key_len)) != CRYPT_OK) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		RETURN_FALSE;
	}

	if (isfilename) {
		char buf[1024];
		long n;

		if (CHECK_NULL_PATH(data, data_len)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid path");
			RETURN_FALSE;
		}
		stream = php_stream_open_wrapper_ex(data, "rb", REPORT_ERRORS, NULL, DEFAULT_CONTEXT);
		if (!stream) {
			/* Stream will report errors opening file */
			RETURN_FALSE;
		}

		while ((n = php_stream_read(stream, buf, sizeof(buf))) > 0) {
			if ((err = php_tomcrypt_mac_descriptors[index].process(&state, (unsigned char *) buf, n)) != CRYPT_OK) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
				RETURN_FALSE;
			}
		}
		php_stream_close(stream);
	} else {
		if ((err = php_tomcrypt_mac_descriptors[index].process(&state, data, data_len)) != CRYPT_OK) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
			RETURN_FALSE;
		}
	}

	if ((err = php_tomcrypt_mac_descriptors[index].done(&state, mac, &macsize)) != CRYPT_OK) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		RETURN_FALSE;
	}

	mac[macsize] = '\0';

	if (raw_output) {
		PLTC_RETURN_STRINGL(mac, macsize, 1);
	} else {
		char *hex_digest = safe_emalloc(macsize, 2, 1);

		php_tomcrypt_bin2hex(hex_digest, (unsigned char *) mac, macsize);
		hex_digest[2 * macsize] = '\0';
		PLTC_RETURN_STRINGL(hex_digest, 2 * macsize, 0);
	}
}
/* }}} */

/* {{{ proto int tomcrypt_mac_string(string algo, string cipher_hash, string key, string data, bool raw_output = false)
   Compute the Message Authentication Code of a string using the specified MAC algorithm and hash/cipher */
PHP_FUNCTION(tomcrypt_mac_string)
{
	php_tomcrypt_do_mac(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}

/* {{{ proto int tomcrypt_mac_file(string algo, string cipher_hash, string key, string filename, bool raw_output = false)
   Compute the Message Authentication Code of a file using the specified MAC algorithm and hash/cipher */
PHP_FUNCTION(tomcrypt_mac_file)
{
	php_tomcrypt_do_mac(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}

