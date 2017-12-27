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

#ifndef PHP_TOMCRYPT_MAC_H
#define PHP_TOMCRYPT_MAC_H

#include "php_tomcrypt_compat.h"

#define PHP_TOMCRYPT_MAC_BLAKE2B    "blake2b"
#define PHP_TOMCRYPT_MAC_BLAKE2S    "blake2s"
#define PHP_TOMCRYPT_MAC_CMAC       "cmac"
#define PHP_TOMCRYPT_MAC_F9         "f9"
#define PHP_TOMCRYPT_MAC_HMAC       "hmac"
#define PHP_TOMCRYPT_MAC_PELICAN    "pelican"
#define PHP_TOMCRYPT_MAC_PMAC       "pmac"
#define PHP_TOMCRYPT_MAC_POLY1305   "poly1305"
#define PHP_TOMCRYPT_MAC_XCBC       "xcbc"

int init_macs(int module_number TSRMLS_DC);

#endif /* PHP_TOMCRYPT_MAC_H */
