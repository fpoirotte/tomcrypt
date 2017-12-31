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
#include "php_tomcrypt_hash.h"
#include "php_tomcrypt_utils.h"

#ifdef LTC_BLAKE2B
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_160 &blake2b_160_desc
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_256 &blake2b_256_desc
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_384 &blake2b_384_desc
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_512 &blake2b_512_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_160 NULL
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_256 NULL
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_384 NULL
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2B_512 NULL
#endif

#ifdef LTC_BLAKE2S
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_128 &blake2s_128_desc
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_160 &blake2s_160_desc
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_224 &blake2s_224_desc
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_256 &blake2s_256_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_128 NULL
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_160 NULL
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_224 NULL
#define PHP_TOMCRYPT_DESC_HASH_BLAKE2S_256 NULL
#endif

#ifdef LTC_MD2
#define PHP_TOMCRYPT_DESC_HASH_MD2 &md2_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_MD2 NULL
#endif

#ifdef LTC_MD4
#define PHP_TOMCRYPT_DESC_HASH_MD4 &md4_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_MD4 NULL
#endif

#ifdef LTC_MD5
#define PHP_TOMCRYPT_DESC_HASH_MD5 &md5_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_MD5 NULL
#endif

#ifdef LTC_RIPEMD128
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD128 &rmd128_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD128 NULL
#endif

#ifdef LTC_RIPEMD160
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD160 &rmd160_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD160 NULL
#endif

#ifdef LTC_RIPEMD256
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD256 &rmd256_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD256 NULL
#endif

#ifdef LTC_RIPEMD320
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD320 &rmd320_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_RIPEMD320 NULL
#endif

#ifdef LTC_SHA1
#define PHP_TOMCRYPT_DESC_HASH_SHA1 &sha1_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA1 NULL
#endif

#ifdef LTC_SHA224
#define PHP_TOMCRYPT_DESC_HASH_SHA224 &sha224_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA2_224 &sha224_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA224 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA2_224 NULL
#endif

#ifdef LTC_SHA256
#define PHP_TOMCRYPT_DESC_HASH_SHA256 &sha256_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA2_256 &sha256_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA256 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA2_256 NULL
#endif

#ifdef LTC_SHA384
#define PHP_TOMCRYPT_DESC_HASH_SHA384 &sha384_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA2_384 &sha384_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA384 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA2_384 NULL
#endif

#ifdef LTC_SHA512
#define PHP_TOMCRYPT_DESC_HASH_SHA512 &sha512_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA2_512 &sha512_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA512 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA2_512 NULL
#endif

#if defined(LTC_SHA512_224) && defined(LTC_SHA512)
#define PHP_TOMCRYPT_DESC_HASH_SHA512_224 &sha512_224_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA2_512_224 &sha512_224_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA512_224 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA2_512_224 NULL
#endif

#if defined(LTC_SHA512_256) && defined(LTC_SHA512)
#define PHP_TOMCRYPT_DESC_HASH_SHA512_256 &sha512_256_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA2_512_256 &sha512_256_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA512_256 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA2_512_256 NULL
#endif

#ifdef LTC_SHA3
#define PHP_TOMCRYPT_DESC_HASH_SHA3_224 &sha3_224_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA3_256 &sha3_256_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA3_384 &sha3_384_desc
#define PHP_TOMCRYPT_DESC_HASH_SHA3_512 &sha3_512_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_SHA3_224 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA3_256 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA3_384 NULL
#define PHP_TOMCRYPT_DESC_HASH_SHA3_512 NULL
#endif

#ifdef LTC_TIGER
#define PHP_TOMCRYPT_DESC_HASH_TIGER &tiger_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_TIGER NULL
#endif

#ifdef LTC_WHIRLPOOL
#define PHP_TOMCRYPT_DESC_HASH_WHIRLPOOL &whirlpool_desc
#else
#define PHP_TOMCRYPT_DESC_HASH_WHIRLPOOL NULL
#endif


#define TOMCRYPT_DEFINE_HASH(alg) \
    if (PHP_TOMCRYPT_DESC_HASH_ ## alg != NULL && register_hash(PHP_TOMCRYPT_DESC_HASH_ ## alg) == -1) { \
		return -1; \
	} \
	REGISTER_STRING_CONSTANT("TOMCRYPT_HASH_" # alg, PHP_TOMCRYPT_HASH_ ## alg, CONST_PERSISTENT | CONST_CS);

int init_hashes(int module_number TSRMLS_DC)
{
	TOMCRYPT_DEFINE_HASH(BLAKE2B_160);
	TOMCRYPT_DEFINE_HASH(BLAKE2B_256);
	TOMCRYPT_DEFINE_HASH(BLAKE2B_384);
	TOMCRYPT_DEFINE_HASH(BLAKE2B_512);
	TOMCRYPT_DEFINE_HASH(BLAKE2S_128);
	TOMCRYPT_DEFINE_HASH(BLAKE2S_160);
	TOMCRYPT_DEFINE_HASH(BLAKE2S_224);
	TOMCRYPT_DEFINE_HASH(BLAKE2S_256);
	TOMCRYPT_DEFINE_HASH(MD2);
	TOMCRYPT_DEFINE_HASH(MD4);
	TOMCRYPT_DEFINE_HASH(MD5);
	TOMCRYPT_DEFINE_HASH(RIPEMD128);
	TOMCRYPT_DEFINE_HASH(RIPEMD160);
	TOMCRYPT_DEFINE_HASH(RIPEMD256);
	TOMCRYPT_DEFINE_HASH(RIPEMD320);
	TOMCRYPT_DEFINE_HASH(SHA1);
	/* Aliases for SHA-2 */
	TOMCRYPT_DEFINE_HASH(SHA2_224);
	TOMCRYPT_DEFINE_HASH(SHA2_256);
	TOMCRYPT_DEFINE_HASH(SHA2_384);
	TOMCRYPT_DEFINE_HASH(SHA2_512);
	TOMCRYPT_DEFINE_HASH(SHA2_512_224);
	TOMCRYPT_DEFINE_HASH(SHA2_512_256);
	TOMCRYPT_DEFINE_HASH(SHA3_224);
	TOMCRYPT_DEFINE_HASH(SHA3_256);
	TOMCRYPT_DEFINE_HASH(SHA3_384);
	TOMCRYPT_DEFINE_HASH(SHA3_512);
	TOMCRYPT_DEFINE_HASH(TIGER);
	TOMCRYPT_DEFINE_HASH(WHIRLPOOL);

	TOMCRYPT_DEFINE_HASH(SHA224);
	TOMCRYPT_DEFINE_HASH(SHA256);
	TOMCRYPT_DEFINE_HASH(SHA384);
	TOMCRYPT_DEFINE_HASH(SHA512);
	TOMCRYPT_DEFINE_HASH(SHA512_224);
	TOMCRYPT_DEFINE_HASH(SHA512_256);
	return 0;
}

/* {{{ proto array tomcrypt_list_hashes()
   List all available hash algorithms */
PHP_FUNCTION(tomcrypt_list_hashes)
{
	int   i;

	array_init(return_value);
	for (i = 0; hash_descriptor[i].name != NULL; i++) {
		pltc_add_index_string(return_value, i, hash_descriptor[i].name, 1);
	}
}
/* }}} */

static void php_tomcrypt_do_hash(INTERNAL_FUNCTION_PARAMETERS, int isfilename) /* {{{ */
{
	char       *algo, *data, hash[MAXBLOCKSIZE + 1];
	pltc_size   algo_len, data_len;
	int         index, err;
	hash_state  md;
	zend_bool   raw_output = 0;
	php_stream *stream = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|b",
		&algo, &algo_len, &data, &data_len, &raw_output) == FAILURE) {
		return;
	}

	if ((index = find_hash(algo)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown hashing algorithm: %s", algo);
		RETURN_FALSE;
	}

	hash_descriptor[index].init(&md);
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
			if ((err = hash_descriptor[index].process(&md, (unsigned char *) buf, n)) != CRYPT_OK) {
				TOMCRYPT_G(last_error) = err;
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
				RETURN_FALSE;
			}
		}
		php_stream_close(stream);
	} else {
		if ((err = hash_descriptor[index].process(&md, data, data_len)) != CRYPT_OK) {
			TOMCRYPT_G(last_error) = err;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
			RETURN_FALSE;
		}
	}

	hash_descriptor[index].done(&md, hash);
	hash[hash_descriptor[index].hashsize] = '\0';

	if (raw_output) {
		PLTC_RETURN_STRINGL(hash, hash_descriptor[index].hashsize, 1);
	} else {
		char *hex_digest = safe_emalloc(hash_descriptor[index].hashsize, 2, 1);

		php_tomcrypt_bin2hex(hex_digest, (unsigned char *) hash, hash_descriptor[index].hashsize);
		hex_digest[2 * hash_descriptor[index].hashsize] = '\0';
		PLTC_RETURN_STRINGL(hex_digest, 2 * hash_descriptor[index].hashsize, 0);
	}
}
/* }}} */

/* {{{ proto int tomcrypt_hash_block_size(string hash)
   Get the block size of the specified hashing algorithm in bytes */
PHP_FUNCTION(tomcrypt_hash_block_size)
{
	char      *algo;
	pltc_size  algo_len;
	int        index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
		&algo, &algo_len) == FAILURE) {
		return;
	}

	if ((index = find_hash(algo)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown hashing algorithm: %s", algo);
		RETURN_FALSE;
	}

	RETVAL_LONG(hash_descriptor[index].blocksize);
}
/* }}} */

/* {{{ proto int tomcrypt_hash_digest_size(string hash)
   Get the digest output size of the specified hashing algorithm in bytes */
PHP_FUNCTION(tomcrypt_hash_digest_size)
{
	char      *algo;
	pltc_size  algo_len;
	int        index;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
		&algo, &algo_len) == FAILURE) {
		return;
	}

	if ((index = find_hash(algo)) == -1) {
		TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unknown hashing algorithm: %s", algo);
		RETURN_FALSE;
	}

	RETVAL_LONG(hash_descriptor[index].hashsize);
}
/* }}} */

/* {{{ proto int tomcrypt_hash_string(string algo, string data, bool raw_output = false)
   Compute the hash of a string using the specified algorithm */
PHP_FUNCTION(tomcrypt_hash_string)
{
	php_tomcrypt_do_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}
/* }}} */

/* {{{ proto int tomcrypt_hash_file(string algo, string filename, bool raw_output = false)
   Compute the hash of a file using the specified algorithm */
PHP_FUNCTION(tomcrypt_hash_file)
{
	php_tomcrypt_do_hash(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
}
/* }}} */

