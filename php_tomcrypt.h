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

#ifndef PHP_TOMCRYPT_H
#define PHP_TOMCRYPT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_LIBTOMCRYPT

#ifdef ZTS
#include "TSRM.h"
#endif


#define PHP_TOMCRYPT_EXTNAME        "tomcrypt"
#define PHP_TOMCRYPT_VERSION        "0.2.4"

/* MAC protocols */
#define PHP_TOMCRYPT_MAC_HMAC       "hmac"
#define PHP_TOMCRYPT_MAC_BLAKE2B    "blake2b"
#define PHP_TOMCRYPT_MAC_BLAKE2S    "blake2s"
#define PHP_TOMCRYPT_MAC_CMAC       "cmac"
#define PHP_TOMCRYPT_MAC_PMAC       "pmac"
#define PHP_TOMCRYPT_MAC_PELICAN    "pelican"
#define PHP_TOMCRYPT_MAC_POLY1305   "poly1305"
#define PHP_TOMCRYPT_MAC_XCBC       "xcbc"
#define PHP_TOMCRYPT_MAC_F9         "f9"

/* Regular modes */
#define PHP_TOMCRYPT_MODE_ECB       "ecb"
#define PHP_TOMCRYPT_MODE_CFB       "cfb"
#define PHP_TOMCRYPT_MODE_OFB       "ofb"
#define PHP_TOMCRYPT_MODE_CBC       "cbc"
#define PHP_TOMCRYPT_MODE_CTR       "ctr"
#define PHP_TOMCRYPT_MODE_LRW       "lrw"
#define PHP_TOMCRYPT_MODE_F8        "f8"
#define PHP_TOMCRYPT_MODE_XTS       "xts"

/* AEAD modes */
#define PHP_TOMCRYPT_MODE_CCM       "ccm"
#define PHP_TOMCRYPT_MODE_GCM       "gcm"
#define PHP_TOMCRYPT_MODE_EAX       "eax"
#define PHP_TOMCRYPT_MODE_OCB       "ocb"

/* RNGs */
#define PHP_TOMCRYPT_RNG_CHACHA20   "chacha20"
#define PHP_TOMCRYPT_RNG_FORTUNA    "fortuna"
#define PHP_TOMCRYPT_RNG_RC4        "rc4"
#define PHP_TOMCRYPT_RNG_SOBER128   "sober128"
#define PHP_TOMCRYPT_RNG_SECURE     "sprng"
#define PHP_TOMCRYPT_RNG_YARROW     "yarrow"

extern zend_module_entry tomcrypt_module_entry;
#define tomcrypt_module_ptr &tomcrypt_module_entry

/* Miscelleanous functions */
PHP_FUNCTION(tomcrypt_strerror);

/* Various lists */
PHP_FUNCTION(tomcrypt_list_modes);
PHP_FUNCTION(tomcrypt_list_ciphers);
PHP_FUNCTION(tomcrypt_list_hashes);
PHP_FUNCTION(tomcrypt_list_macs);
PHP_FUNCTION(tomcrypt_list_rngs);

/* Cipher-related functions */
PHP_FUNCTION(tomcrypt_cipher_name);
PHP_FUNCTION(tomcrypt_cipher_block_size);
PHP_FUNCTION(tomcrypt_cipher_adapt_key_size);
PHP_FUNCTION(tomcrypt_cipher_min_key_size);
PHP_FUNCTION(tomcrypt_cipher_max_key_size);
PHP_FUNCTION(tomcrypt_cipher_default_rounds);
PHP_FUNCTION(tomcrypt_cipher_encrypt);
PHP_FUNCTION(tomcrypt_cipher_decrypt);

/* Hash-related functions */
PHP_FUNCTION(tomcrypt_hash_name);
PHP_FUNCTION(tomcrypt_hash_block_size);
PHP_FUNCTION(tomcrypt_hash_digest_size);
PHP_FUNCTION(tomcrypt_hash_string);
PHP_FUNCTION(tomcrypt_hash_file);

/* MAC-related functions */
PHP_FUNCTION(tomcrypt_mac_string);
PHP_FUNCTION(tomcrypt_mac_file);

/* RNG-related functions */
PHP_FUNCTION(tomcrypt_rng_name);
PHP_FUNCTION(tomcrypt_rng_get_bytes);


static inline void php_tomcrypt_bin2hex(char *out, const unsigned char *in, int in_len)
{
	static const char hexits[17] = "0123456789abcdef";
	int i;

	for(i = 0; i < in_len; i++) {
		out[i * 2]       = hexits[in[i] >> 4];
		out[(i * 2) + 1] = hexits[in[i] &  0x0F];
	}
}

#else
#define tomcrypt_module_ptr NULL
#endif

#define phpext_tomcrypt_ptr tomcrypt_module_ptr

#endif	/* PHP_TOMCRYPT_H */
