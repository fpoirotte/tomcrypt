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

#ifndef PHP_TOMCRYPT_HASH_H
#define PHP_TOMCRYPT_HASH_H

#include "php_tomcrypt_compat.h"

#define PHP_TOMCRYPT_HASH_BLAKE2B_160   "blake2b-160"
#define PHP_TOMCRYPT_HASH_BLAKE2B_256   "blake2b-256"
#define PHP_TOMCRYPT_HASH_BLAKE2B_384   "blake2b-384"
#define PHP_TOMCRYPT_HASH_BLAKE2B_512   "blake2b-512"
#define PHP_TOMCRYPT_HASH_BLAKE2S_128   "blake2s-128"
#define PHP_TOMCRYPT_HASH_BLAKE2S_160   "blake2s-160"
#define PHP_TOMCRYPT_HASH_BLAKE2S_224   "blake2s-224"
#define PHP_TOMCRYPT_HASH_BLAKE2S_256   "blake2s-256"
#define PHP_TOMCRYPT_HASH_MD2           "md2"
#define PHP_TOMCRYPT_HASH_MD4           "md4"
#define PHP_TOMCRYPT_HASH_MD5           "md5"
#define PHP_TOMCRYPT_HASH_RIPEMD128     "rmd128"
#define PHP_TOMCRYPT_HASH_RIPEMD160     "rmd160"
#define PHP_TOMCRYPT_HASH_RIPEMD256     "rmd256"
#define PHP_TOMCRYPT_HASH_RIPEMD320     "rmd320"
#define PHP_TOMCRYPT_HASH_SHA1          "sha1"
#define PHP_TOMCRYPT_HASH_SHA224        "sha224"
#define PHP_TOMCRYPT_HASH_SHA256        "sha256"
#define PHP_TOMCRYPT_HASH_SHA384        "sha384"
#define PHP_TOMCRYPT_HASH_SHA512        "sha512"
#define PHP_TOMCRYPT_HASH_SHA512_224    "sha512-224"
#define PHP_TOMCRYPT_HASH_SHA512_256    "sha512-256"
#define PHP_TOMCRYPT_HASH_SHA3_224      "sha3-224"
#define PHP_TOMCRYPT_HASH_SHA3_256      "sha3-256"
#define PHP_TOMCRYPT_HASH_SHA3_384      "sha3-384"
#define PHP_TOMCRYPT_HASH_SHA3_512      "sha3-512"
#define PHP_TOMCRYPT_HASH_TIGER         "tiger"
#define PHP_TOMCRYPT_HASH_WHIRLPOOL     "whirlpool"

int init_hashes(int module_number TSRMLS_DC);

#endif /* PHP_TOMCRYPT_HASH_H */
