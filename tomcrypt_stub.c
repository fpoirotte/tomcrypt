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

#include "php_tomcrypt.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include <tomcrypt.h>

/* {{{ tomcrypt_module_entry
 */
zend_module_entry tomcrypt_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"tomcrypt",
	NULL, /* functions */
	PHP_MINIT(tomcrypt),
	PHP_MSHUTDOWN(tomcrypt),
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	PHP_MINFO(tomcrypt),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_TOMCRYPT_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_TOMCRYPT
ZEND_GET_MODULE(tomcrypt)
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(tomcrypt)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(tomcrypt)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(tomcrypt)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "tomcrypt support", "enabled");
	php_info_print_table_header(2, "extension version", PHP_TOMCRYPT_VERSION);
	php_info_print_table_header(2, "tomcrypt version", SCRYPT);
	php_info_print_table_end();
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
