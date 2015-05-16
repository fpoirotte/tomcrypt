/*
  +----------------------------------------------------------------------+
  | PHP Version 4                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2015 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.02 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available at through the world-wide-web at                           |
  | http://www.php.net/license/2_02.txt.                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: François Poirotte <clicky@erebot.net>                        |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef PHP_TOMCRYPT_H
#define PHP_TOMCRYPT_H

#include "php.h"

#define PHP_TOMCRYPT_EXTNAME "tomcrypt"
#define PHP_TOMCRYPT_VERSION "0.0.1"

extern zend_module_entry tomcrypt_module_entry;
#define phpext_tomcrypt_ptr &tomcrypt_module_entry

PHP_MINIT_FUNCTION(tomcrypt);
PHP_MSHUTDOWN_FUNCTION(tomcrypt);
PHP_MINFO_FUNCTION(tomcrypt);

#endif	/* PHP_TOMCRYPT_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */
