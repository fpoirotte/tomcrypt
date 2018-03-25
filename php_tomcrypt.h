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


#define PHP_TOMCRYPT_EXTNAME        "tomcrypt"
#define PHP_TOMCRYPT_VERSION        "0.3.2"

extern zend_module_entry tomcrypt_module_entry;
#define tomcrypt_module_ptr &tomcrypt_module_entry

/* Miscelleanous functions */
PHP_FUNCTION(tomcrypt_clear);
PHP_FUNCTION(tomcrypt_error);
PHP_FUNCTION(tomcrypt_errno);
PHP_FUNCTION(tomcrypt_hkdf);

/* Modes-related functions */
PHP_FUNCTION(tomcrypt_list_modes);

/* Cipher-related functions */
PHP_FUNCTION(tomcrypt_list_ciphers);
PHP_FUNCTION(tomcrypt_cipher_block_size);
PHP_FUNCTION(tomcrypt_cipher_adapt_key_size);
PHP_FUNCTION(tomcrypt_cipher_min_key_size);
PHP_FUNCTION(tomcrypt_cipher_max_key_size);
PHP_FUNCTION(tomcrypt_cipher_default_rounds);
PHP_FUNCTION(tomcrypt_cipher_encrypt);
PHP_FUNCTION(tomcrypt_cipher_decrypt);

/* Hash-related functions */
PHP_FUNCTION(tomcrypt_list_hashes);
PHP_FUNCTION(tomcrypt_hash_block_size);
PHP_FUNCTION(tomcrypt_hash_digest_size);
PHP_FUNCTION(tomcrypt_hash_string);
PHP_FUNCTION(tomcrypt_hash_file);

/* MAC-related functions */
PHP_FUNCTION(tomcrypt_list_macs);
PHP_FUNCTION(tomcrypt_mac_string);
PHP_FUNCTION(tomcrypt_mac_file);

/* RNG-related functions */
PHP_FUNCTION(tomcrypt_list_rngs);
PHP_FUNCTION(tomcrypt_rng_get_bytes);

#else
#define tomcrypt_module_ptr NULL
#endif

#define phpext_tomcrypt_ptr tomcrypt_module_ptr

#endif	/* PHP_TOMCRYPT_H */
