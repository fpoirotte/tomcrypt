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

#ifndef PHP_TOMCRYPT_CIPHER_H
#define PHP_TOMCRYPT_CIPHER_H

#include "php_tomcrypt_compat.h"

#define PHP_TOMCRYPT_CIPHER_3DES        "3des"
#define PHP_TOMCRYPT_CIPHER_AES         "aes"
#define PHP_TOMCRYPT_CIPHER_ANUBIS      "anubis"
#define PHP_TOMCRYPT_CIPHER_BLOWFISH    "blowfish"
#define PHP_TOMCRYPT_CIPHER_CAMELLIA    "camellia"
#define PHP_TOMCRYPT_CIPHER_CAST5       "cast5"
#define PHP_TOMCRYPT_CIPHER_DES         "des"
#define PHP_TOMCRYPT_CIPHER_KASUMI      "kasumi"
#define PHP_TOMCRYPT_CIPHER_KHAZAD      "khazad"
#define PHP_TOMCRYPT_CIPHER_MULTI2      "multi2"
#define PHP_TOMCRYPT_CIPHER_NOEKEON     "noekeon"
#define PHP_TOMCRYPT_CIPHER_RC2         "rc2"
#define PHP_TOMCRYPT_CIPHER_RC5         "rc5"
#define PHP_TOMCRYPT_CIPHER_RC6         "rc6"
/* We just make Rijndael an alias for AES.
   LibTomCrypt uses the same implementation for both algorithms. */
#define PHP_TOMCRYPT_CIPHER_RIJNDAEL    "aes"
#define PHP_TOMCRYPT_CIPHER_SAFER64     "safer-sk64"
#define PHP_TOMCRYPT_CIPHER_SAFER128    "safer-sk128"
#define PHP_TOMCRYPT_CIPHER_SAFERK64    "safer-k64"
#define PHP_TOMCRYPT_CIPHER_SAFERK128   "safer-k128"
#define PHP_TOMCRYPT_CIPHER_SAFERPLUS   "safer+"
#define PHP_TOMCRYPT_CIPHER_SAFERSK64   "safer-sk64"
#define PHP_TOMCRYPT_CIPHER_SAFERSK128  "safer-sk128"
#define PHP_TOMCRYPT_CIPHER_SEED        "seed"
#define PHP_TOMCRYPT_CIPHER_SKIPJACK    "skipjack"
#define PHP_TOMCRYPT_CIPHER_TRIPLEDES   "3des"
#define PHP_TOMCRYPT_CIPHER_TWOFISH     "twofish"
#define PHP_TOMCRYPT_CIPHER_XTEA        "xtea"

int init_ciphers(int module_number TSRMLS_DC);

#endif /* PHP_TOMCRYPT_CIPHER_H */
