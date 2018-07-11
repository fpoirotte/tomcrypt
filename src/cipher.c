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

#include <stdlib.h>
#include <tomcrypt.h>
#include "cipher.h"
#include "mode.h"
#include "modes/crypt_mode.h"

#ifdef LTC_RIJNDAEL
#define PHP_TOMCRYPT_DESC_CIPHER_AES      &aes_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_AES      NULL
#endif

#ifdef LTC_ANUBIS
#define PHP_TOMCRYPT_DESC_CIPHER_ANUBIS &anubis_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_ANUBIS NULL
#endif

#ifdef LTC_BLOWFISH
#define PHP_TOMCRYPT_DESC_CIPHER_BLOWFISH &blowfish_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_BLOWFISH NULL
#endif

#ifdef LTC_CAMELLIA
#define PHP_TOMCRYPT_DESC_CIPHER_CAMELLIA &camellia_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_CAMELLIA NULL
#endif

#ifdef LTC_CAST5
#define PHP_TOMCRYPT_DESC_CIPHER_CAST5 &cast5_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_CAST5 NULL
#endif

/* Hack for the ChaCha stream cipher. */
#define PHP_TOMCRYPT_DESC_CIPHER_CHACHA NULL

#ifdef LTC_DES
#define PHP_TOMCRYPT_DESC_CIPHER_DES       &des_desc
#define PHP_TOMCRYPT_DESC_CIPHER_3DES      &des3_desc
#define PHP_TOMCRYPT_DESC_CIPHER_TRIPLEDES &des3_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_DES       NULL
#define PHP_TOMCRYPT_DESC_CIPHER_3DES      NULL
#define PHP_TOMCRYPT_DESC_CIPHER_TRIPLEDES NULL
#endif

#ifdef LTC_KASUMI
#define PHP_TOMCRYPT_DESC_CIPHER_KASUMI &kasumi_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_KASUMI NULL
#endif

#ifdef LTC_KHAZAD
#define PHP_TOMCRYPT_DESC_CIPHER_KHAZAD &khazad_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_KHAZAD NULL
#endif

#ifdef LTC_MULTI2
#define PHP_TOMCRYPT_DESC_CIPHER_MULTI2 &multi2_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_MULTI2 NULL
#endif

#ifdef LTC_NOEKEON
#define PHP_TOMCRYPT_DESC_CIPHER_NOEKEON &noekeon_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_NOEKEON NULL
#endif

#ifdef LTC_RC2
#define PHP_TOMCRYPT_DESC_CIPHER_RC2 &rc2_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_RC2 NULL
#endif

/* Hack for the RC4 stream cipher. */
#define PHP_TOMCRYPT_DESC_CIPHER_RC4 NULL

#ifdef LTC_RC5
#define PHP_TOMCRYPT_DESC_CIPHER_RC5 &rc5_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_RC5 NULL
#endif

#ifdef LTC_RC6
#define PHP_TOMCRYPT_DESC_CIPHER_RC6 &rc6_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_RC6 NULL
#endif

#ifdef LTC_RIJNDAEL
/* We just make Rijndael an alias for AES.
   LibTomCrypt uses the same implementation for both algorithms. */
#define PHP_TOMCRYPT_DESC_CIPHER_RIJNDAEL &aes_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_RIJNDAEL NULL
#endif

#ifdef LTC_SAFER
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERK64   &safer_k64_desc
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERK128  &safer_k128_desc
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERSK64  &safer_sk64_desc
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERSK128 &safer_sk128_desc
#define PHP_TOMCRYPT_DESC_CIPHER_SAFER64    &safer_sk64_desc
#define PHP_TOMCRYPT_DESC_CIPHER_SAFER128   &safer_sk128_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERK64   NULL
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERK128  NULL
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERSK64  NULL
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERSK128 NULL
#define PHP_TOMCRYPT_DESC_CIPHER_SAFER64    NULL
#define PHP_TOMCRYPT_DESC_CIPHER_SAFER128   NULL
#endif

#ifdef LTC_SAFERP
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERPLUS &saferp_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_SAFERPLUS NULL
#endif

#ifdef LTC_KSEED
#define PHP_TOMCRYPT_DESC_CIPHER_SEED &kseed_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_SEED NULL
#endif

#ifdef LTC_SKIPJACK
#define PHP_TOMCRYPT_DESC_CIPHER_SKIPJACK &skipjack_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_SKIPJACK NULL
#endif

/* Hack for the Sober128 stream cipher. */
#define PHP_TOMCRYPT_DESC_CIPHER_SOBER128 NULL

#ifdef LTC_TWOFISH
#define PHP_TOMCRYPT_DESC_CIPHER_TWOFISH &twofish_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_TWOFISH NULL
#endif

#ifdef LTC_XTEA
#define PHP_TOMCRYPT_DESC_CIPHER_XTEA &xtea_desc
#else
#define PHP_TOMCRYPT_DESC_CIPHER_XTEA NULL
#endif



/* "null" family of ciphers */
extern const struct ltc_cipher_descriptor null_desc, null_128_desc;
#define PHP_TOMCRYPT_DESC_CIPHER_NULL_REGULAR   &null_desc
#define PHP_TOMCRYPT_DESC_CIPHER_NULL_128       &null_128_desc


#define TOMCRYPT_DEFINE_CIPHER(cname) \
    if (PHP_TOMCRYPT_DESC_CIPHER_ ## cname != NULL && register_cipher(PHP_TOMCRYPT_DESC_CIPHER_ ## cname) == -1) { \
		return -1; \
	} \
	REGISTER_STRING_CONSTANT("TOMCRYPT_CIPHER_" # cname, PHP_TOMCRYPT_CIPHER_ ## cname, CONST_PERSISTENT | CONST_CS);


int init_ciphers(int module_number TSRMLS_DC)
{
	TOMCRYPT_DEFINE_CIPHER(3DES);
	TOMCRYPT_DEFINE_CIPHER(AES);
	TOMCRYPT_DEFINE_CIPHER(ANUBIS);
	TOMCRYPT_DEFINE_CIPHER(BLOWFISH);
	TOMCRYPT_DEFINE_CIPHER(CAMELLIA);
	TOMCRYPT_DEFINE_CIPHER(CAST5);
	TOMCRYPT_DEFINE_CIPHER(CHACHA); /* Stream cipher */
	TOMCRYPT_DEFINE_CIPHER(DES);
	TOMCRYPT_DEFINE_CIPHER(KASUMI);
	TOMCRYPT_DEFINE_CIPHER(KHAZAD);
	TOMCRYPT_DEFINE_CIPHER(MULTI2);
	TOMCRYPT_DEFINE_CIPHER(NOEKEON);
	TOMCRYPT_DEFINE_CIPHER(RC2);
	TOMCRYPT_DEFINE_CIPHER(RC4); /* Stream cipher */
	TOMCRYPT_DEFINE_CIPHER(RC5);
	TOMCRYPT_DEFINE_CIPHER(RC6);
	TOMCRYPT_DEFINE_CIPHER(RIJNDAEL);
	TOMCRYPT_DEFINE_CIPHER(SAFER64);
	TOMCRYPT_DEFINE_CIPHER(SAFER128);
	TOMCRYPT_DEFINE_CIPHER(SAFERK64);
	TOMCRYPT_DEFINE_CIPHER(SAFERK128);
	TOMCRYPT_DEFINE_CIPHER(SAFERPLUS);
	TOMCRYPT_DEFINE_CIPHER(SAFERSK64);
	TOMCRYPT_DEFINE_CIPHER(SAFERSK128);
	TOMCRYPT_DEFINE_CIPHER(SEED);
	TOMCRYPT_DEFINE_CIPHER(SKIPJACK);
	TOMCRYPT_DEFINE_CIPHER(SOBER128); /* Stream cipher */
	TOMCRYPT_DEFINE_CIPHER(TRIPLEDES);
	TOMCRYPT_DEFINE_CIPHER(TWOFISH);
	TOMCRYPT_DEFINE_CIPHER(XTEA);

    /* We only expose the "null" family of ciphers if PLTC_NULL has been
       defined in the interpreter's environment before execution. */
    if (getenv("PLTC_NULL") != NULL) {
        TOMCRYPT_DEFINE_CIPHER(NULL_REGULAR);
        TOMCRYPT_DEFINE_CIPHER(NULL_128);
    }

	return 0;
}

/* {{{ proto array tomcrypt_list_ciphers()
   List all available ciphers */
PHP_FUNCTION(tomcrypt_list_ciphers)
{
	int   i;

	if (zend_parse_parameters_none() == FAILURE) {
	    return;
	}

	array_init(return_value);
	for (i = 0; cipher_descriptor[i].name != NULL; i++) {
		pltc_add_index_string(return_value, i, cipher_descriptor[i].name, 1);
	}
}
/* }}} */

/* {{{ proto int tomcrypt_cipher_block_size(string cipher)
   Get the block size of the specified cipher in bytes */
PHP_FUNCTION(tomcrypt_cipher_block_size)
{
	char      *cipher;
	pltc_size cipher_len;
	int       index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
		&cipher, &cipher_len) == FAILURE) {
		return;
	}

	if ((index = find_cipher(cipher)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher: %s", cipher);
		RETURN_FALSE;
	}

	RETVAL_LONG(cipher_descriptor[index].block_length);
}
/* }}} */

/* {{{ proto int tomcrypt_cipher_adapt_key_size(string cipher, int keysize)
   Derive an appropriate key size for the specified cipher */
PHP_FUNCTION(tomcrypt_cipher_adapt_key_size)
{
	char      *cipher;
	pltc_size cipher_len;
	int       index, err, size;
	pltc_long keysize;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl",
		&cipher, &cipher_len, &keysize) == FAILURE) {
		return;
	}

	if ((index = find_cipher(cipher)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher: %s", cipher);
		RETURN_FALSE;
	}

	/* Detect key sizes that would cause issues (eg. overflows). */
	size = (keysize < 0 || keysize >= 0xFFFFFFFF) ? 0 : (int) keysize;

	if ((err = cipher_descriptor[index].keysize(&size)) != CRYPT_OK) {
		TOMCRYPT_G(last_error) = err;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		RETURN_FALSE;
	}

	RETVAL_LONG((long) size);
}
/* }}} */

/* {{{ proto int tomcrypt_cipher_min_key_size(string cipher)
   Get the minimum key size of the specified cipher in bytes */
PHP_FUNCTION(tomcrypt_cipher_min_key_size)
{
	char      *cipher;
	pltc_size cipher_len;
	int       index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
		&cipher, &cipher_len) == FAILURE) {
		return;
	}

	if ((index = find_cipher(cipher)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher: %s", cipher);
		RETURN_FALSE;
	}

	RETVAL_LONG(cipher_descriptor[index].min_key_length);
}
/* }}} */

/* {{{ proto int tomcrypt_cipher_max_key_size(string cipher)
   Get the maximum key size of the specified cipher in bytes */
PHP_FUNCTION(tomcrypt_cipher_max_key_size)
{
	char      *cipher;
	pltc_size cipher_len;
	int       index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
		&cipher, &cipher_len) == FAILURE) {
		return;
	}

	if ((index = find_cipher(cipher)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher: %s", cipher);
		RETURN_FALSE;
	}

	RETVAL_LONG(cipher_descriptor[index].max_key_length);
}
/* }}} */

/* {{{ proto int tomcrypt_cipher_default_rounds(string cipher)
   Get the default number of rounds for the specified cipher */
PHP_FUNCTION(tomcrypt_cipher_default_rounds)
{
	char      *cipher;
	pltc_size cipher_len;
	int       index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
		&cipher, &cipher_len) == FAILURE) {
		return;
	}

	if ((index = find_cipher(cipher)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown cipher: %s", cipher);
		RETURN_FALSE;
	}

	RETVAL_LONG(cipher_descriptor[index].default_rounds);
}
/* }}} */

/* Encrypt or decrypt some data depending on direction */
static void php_tomcrypt_do_crypt(INTERNAL_FUNCTION_PARAMETERS, int direction)
{
	char      *ciphername, *key, *input, *mode;
	pltc_size  ciphername_len, key_len, input_len, mode_len;
	zval      *options = NULL;
	int        cipher = -1;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s!sss|a!",
		&ciphername, &ciphername_len, &key, &key_len, &input, &input_len,
		&mode, &mode_len, &options) == FAILURE) {
		RETURN_FALSE;
	}

	if (!strncmp(PHP_TOMCRYPT_MODE_CHACHA20POLY1305, mode, mode_len)) {
		/* ChaCha20-Poly1305 uses a fixed algorithm and does not require
		   the caller to specify an additional cipher.
		   So, we do nothing here. */
	} else if (!ciphername) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid cipher");
		RETURN_FALSE;
	} else if ((cipher = find_cipher(ciphername)) == -1) {
		/* Only certain ciphers (stream ciphers) can be used in stream mode.
		   Reciprocally, stream mode can only be used with stream ciphers.
		   For now, we're forced to explicitly whitelist stream ciphers. */
		int stream_mode = !strncmp(PHP_TOMCRYPT_MODE_STREAM, mode, mode_len);
		if (!memcmp(ciphername, PHP_TOMCRYPT_CIPHER_RC4, sizeof(PHP_TOMCRYPT_CIPHER_RC4))) {
			cipher = PHP_TOMCRYPT_STREAM_CIPHER_RC4;
		} else if (!memcmp(ciphername, PHP_TOMCRYPT_CIPHER_CHACHA, sizeof(PHP_TOMCRYPT_CIPHER_CHACHA))) {
			cipher = PHP_TOMCRYPT_STREAM_CIPHER_CHACHA;
		} else if (!memcmp(ciphername, PHP_TOMCRYPT_CIPHER_SOBER128, sizeof(PHP_TOMCRYPT_CIPHER_SOBER128))) {
			cipher = PHP_TOMCRYPT_STREAM_CIPHER_SOBER128;
		}

		if (stream_mode && cipher == -1) {
			TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "TOMCRYPT_MODE_STREAM can only be used with stream ciphers");
			RETURN_FALSE;
		} else if (!stream_mode && cipher < -1) {
			TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "This cipher can only be used with TOMCRYPT_MODE_STREAM");
			RETURN_FALSE;
		} else {
			/* The given cipher is really invalid. */
			TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported cipher");
			RETURN_FALSE;
		}
	}

	/* Loop through the handlers in order of decreasing likelihood. */
	/* @TODO sort these by decreasing likelihood */
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_CBC,              php_tomcrypt_xcrypt_cbc)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_CCM,              php_tomcrypt_xcrypt_ccm)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_CFB,              php_tomcrypt_xcrypt_cfb)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_CHACHA20POLY1305, php_tomcrypt_xcrypt_chacha20poly1305)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_CTR,              php_tomcrypt_xcrypt_ctr)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_EAX,              php_tomcrypt_xcrypt_eax)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_ECB,              php_tomcrypt_xcrypt_ecb)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_F8,               php_tomcrypt_xcrypt_f8)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_GCM,              php_tomcrypt_xcrypt_gcm)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_LRW,              php_tomcrypt_xcrypt_lrw)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_OCB,              php_tomcrypt_xcrypt_ocb)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_OCB3,             php_tomcrypt_xcrypt_ocb3)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_OFB,              php_tomcrypt_xcrypt_ofb)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_STREAM,           php_tomcrypt_xcrypt_stream)
	PLTC_CRYPT_HANDLER(PHP_TOMCRYPT_MODE_XTS,              php_tomcrypt_xcrypt_xts)

	/* Unsupported mode (invalid name, not compiled, etc.) */
	TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported mode");
	RETURN_FALSE;
}

/* {{{ proto string tomcrypt_cipher_encrypt(string cipher, string key,
                                            string plaintext, string mode,
                                            &array options = array())
   Encrypt some data */
PHP_FUNCTION(tomcrypt_cipher_encrypt)
{
	php_tomcrypt_do_crypt(INTERNAL_FUNCTION_PARAM_PASSTHRU, PLTC_ENCRYPT);
}
/* }}} */

/* {{{ proto string tomcrypt_cipher_decrypt(string cipher, string key,
                                            string ciphertext, string mode,
                                            array options = array())
   Decrypt some data */
PHP_FUNCTION(tomcrypt_cipher_decrypt)
{
	php_tomcrypt_do_crypt(INTERNAL_FUNCTION_PARAM_PASSTHRU, PLTC_DECRYPT);
}
/* }}} */

