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

#ifndef PHP_TOMCRYPT_COMPAT_H
#define PHP_TOMCRYPT_COMPAT_H

#ifdef ZTS
#include "TSRM.h"
#endif

#include "php.h"
#include "SAPI.h"
#include "ext/standard/file.h"

#ifdef ZEND_ENGINE_3
# include "ext/standard/php_smart_string.h"
#else
# include "ext/standard/php_smart_str.h"
#endif

#ifdef ZEND_ENGINE_3
# define GET_OPT_STRING(arr, key, dest, destlen, defval) { \
	zend_string *str = zend_string_init(key, sizeof(key)-1, 0); \
	zval *item; \
	if (arr && (item = zend_hash_find(Z_ARRVAL_P(arr), str)) != NULL && Z_TYPE_P(item) == IS_STRING) { \
		dest = Z_STRVAL_P(item); \
		destlen = Z_STRLEN_P(item); \
	} else { \
		dest = defval; \
		destlen = (defval == NULL) ? 0 : sizeof(defval); \
	} \
	zend_string_release(str); \
}
# define GET_OPT_LONG(arr, key, dest, defval)	{ \
	zend_string *str = zend_string_init(key, sizeof(key)-1, 0); \
	zval *item; \
	if (arr && (item = zend_hash_find(Z_ARRVAL_P(arr), str)) != NULL && Z_TYPE_P(item) == IS_LONG) \
		dest = Z_LVAL_P(item); \
	else \
		dest = defval; \
	zend_string_release(str); \
}
#define PLTC_REGISTER_STRING_CONSTANT(name, str, flags)  zend_register_string_constant((name), strlen(name), (str), (flags), module_number TSRMLS_CC)
#else
# define GET_OPT_STRING(arr, key, dest, destlen, defval) { \
	zval **item; \
	if (arr && zend_hash_find(Z_ARRVAL_P(arr), key, sizeof(key), (void**)&item) == SUCCESS && Z_TYPE_PP(item) == IS_STRING) { \
		dest = Z_STRVAL_PP(item); \
		destlen = Z_STRLEN_PP(item); \
	} else { \
		dest = defval; \
		destlen = (defval == NULL) ? 0 : sizeof(defval); \
	} \
}
# define GET_OPT_LONG(arr, key, dest, defval)	{ \
	zval **item; \
	if (arr && zend_hash_find(Z_ARRVAL_P(arr), key, sizeof(key), (void**)&item) == SUCCESS && Z_TYPE_PP(item) == IS_LONG) \
		dest = Z_LVAL_PP(item); \
	else \
		dest = defval; \
}
#define PLTC_REGISTER_STRING_CONSTANT(name, str, flags)  zend_register_string_constant((name), strlen(name)+1, (str), (flags), module_number TSRMLS_CC)
#endif

#if (PHP_VERSION_ID >= 50000)
# define DEFAULT_CONTEXT FG(default_context)
#else
# define DEFAULT_CONTEXT NULL
#endif

#if (PHP_VERSION_ID < 50400)
# define CHECK_NULL_PATH(p, l) (strlen(p) != (size_t)l)
# define str_efree(s) { efree(s); }
# define php_output_write php_body_write
#endif

#ifdef ZEND_ENGINE_3
typedef zend_long   pltc_long;
typedef size_t      pltc_size;
# define PLTC_RETVAL_STRING(s, ex) { \
    RETVAL_STRING(s);                \
    if (!ex) efree((void *) s);      \
  }
# define PLTC_RETVAL_STRINGL(s, len, ex) { \
    RETVAL_STRINGL(s, len);                \
    if (!ex) efree((void *) s);            \
  }
# define pltc_add_index_string(zv, idx, s, ex) { \
    add_index_string(zv, idx, s);                \
    if (!ex) efree((void *) s);                  \
  }
# define pltc_add_assoc_stringl(zv, key, s, len, ex) { \
    add_assoc_stringl(zv, key, s, len);                \
    if (!ex) efree((void *) s);                        \
  }
#else
typedef long        pltc_long;
typedef int         pltc_size;
# define PLTC_RETVAL_STRING(s, ex)       RETVAL_STRING(s, ex)
# define PLTC_RETVAL_STRINGL(s, len, ex) RETVAL_STRINGL(s, len, ex)
# define pltc_add_index_string(zv, idx, s, ex) add_index_string(zv, idx, s, ex)
# define pltc_add_assoc_stringl(zv, key, s, len, ex) add_assoc_stringl(zv, key, s, len, ex)
#endif

#define PLTC_RETURN_STRING(s, ex) { \
    PLTC_RETVAL_STRING(s, ex);      \
    return;                         \
}
#define PLTC_RETURN_STRINGL(s, len, ex) { \
    PLTC_RETVAL_STRINGL(s, len, ex);      \
    return;                               \
}

/* Module globals */
ZEND_BEGIN_MODULE_GLOBALS(tomcrypt)
        int last_error;
ZEND_END_MODULE_GLOBALS(tomcrypt)
ZEND_EXTERN_MODULE_GLOBALS(tomcrypt)


#ifdef ZTS
# define TOMCRYPT_G(v) TSRMG(tomcrypt_globals_id, zend_tomcrypt_globals *, v)
#else
# define TOMCRYPT_G(v)     (tomcrypt_globals.v)
#endif

#endif /* PHP_TOMCRYPT_COMPAT_H */
