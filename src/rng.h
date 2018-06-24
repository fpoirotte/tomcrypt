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

#ifndef PHP_TOMCRYPT_RNG_H
#define PHP_TOMCRYPT_RNG_H

#include "compat.h"

#define PHP_TOMCRYPT_RNG_CHACHA20   "chacha20"
#define PHP_TOMCRYPT_RNG_FORTUNA    "fortuna"
#define PHP_TOMCRYPT_RNG_RC4        "rc4"
#define PHP_TOMCRYPT_RNG_SECURE     "secure"
#define PHP_TOMCRYPT_RNG_SOBER128   "sober128"
#define PHP_TOMCRYPT_RNG_YARROW     "yarrow"

int init_rngs(int module_number TSRMLS_DC);
int deinit_rngs(void);

#endif /* PHP_TOMCRYPT_RNG_H */
