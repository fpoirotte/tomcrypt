dnl
dnl $Id: config.m4 180917 2005-02-27 07:09:35Z pollita $
dnl 

PHP_ARG_WITH(tomcrypt, for libtomcrypt support,
[  --with-tomcrypt[=DIR] Include tomcrypt support.])

if test "$PHP_tomcrypt" != "no"; then
  for i in $PHP_tomcrypt /usr/local /usr; do
    test -f $i/include/tomcrypt.h && tomcrypt_DIR=$i && break
  done

  if test -z "$tomcrypt_DIR"; then
    AC_MSG_ERROR(tomcrypt.h not found. Please reinstall libtomcrypt.)
  fi

  PHP_ADD_LIBRARY_WITH_PATH(tomcrypt, $tomcrypt_DIR/lib, TOMCRYPT_SHARED_LIBADD)
  PHP_ADD_INCLUDE($tomcrypt_DIR/include)

  PHP_NEW_EXTENSION(tomcrypt, tomcrypt_stub.c tomcrypt.c, $ext_shared)
  PHP_SUBST(tomcrypt_SHARED_LIBADD)
  AC_DEFINE(HAVE_LIBTOMCRYPT,1,[ ])
fi
