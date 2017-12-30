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

#ifndef PHP_TOMCRYPT_MODE_H
#define PHP_TOMCRYPT_MODE_H

#include "php_tomcrypt_compat.h"

#define PHP_TOMCRYPT_MODE_CBC               "cbc"
#define PHP_TOMCRYPT_MODE_CCM               "ccm"
#define PHP_TOMCRYPT_MODE_CFB               "cfb"
#define PHP_TOMCRYPT_MODE_CHACHA20POLY1305  "chacha20poly1305"
#define PHP_TOMCRYPT_MODE_CTR               "ctr"
#define PHP_TOMCRYPT_MODE_EAX               "eax"
#define PHP_TOMCRYPT_MODE_ECB               "ecb"
#define PHP_TOMCRYPT_MODE_F8                "f8"
#define PHP_TOMCRYPT_MODE_GCM               "gcm"
#define PHP_TOMCRYPT_MODE_LRW               "lrw"
#define PHP_TOMCRYPT_MODE_OCB               "ocb"
#define PHP_TOMCRYPT_MODE_OCB3              "ocb3"
#define PHP_TOMCRYPT_MODE_OFB               "ofb"
#define PHP_TOMCRYPT_MODE_STREAM            "stream" /* Hack for stream ciphers */
#define PHP_TOMCRYPT_MODE_XTS               "xts"

int init_modes(int module_number TSRMLS_DC);

#endif /* PHP_TOMCRYPT_MODE_H */
