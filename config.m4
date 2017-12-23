dnl
dnl $Id$
dnl

PHP_ARG_WITH(tomcrypt, for libtomcrypt support,
[  --with-tomcrypt[=DIR]    Include tomcrypt support])

if test "$PHP_TOMCRYPT" != "no"; then
  for i in $PHP_TOMCRYPT /usr/local /usr; do
    test -f $i/include/tomcrypt.h && TOMCRYPT_DIR=$i && break
  done

  if test -z "$TOMCRYPT_DIR"; then
    AC_MSG_ERROR(tomcrypt.h not found)
  fi

  TOMCRYPT_LIBDIR=$TOMCRYPT_DIR/$PHP_LIBDIR
  TOMCRYPT_INCDIR=$TOMCRYPT_DIR/include

  O_LDFLAGS=$LDFLAGS
  LDFLAGS="$LDFLAGS -L$TOMCRYPT_LIBDIR"
  AC_CHECK_LIB(tomcrypt, find_cipher, [
      TOMCRYPT_LIBS=tomcrypt
      TOMCRYPT_CHECK_IN_LIB=tomcrypt
    ],[
      AC_MSG_ERROR(Unable to find required tomcrypt library)
    ]
  )
  LDFLAGS=$O_LDFLAGS

  AC_DEFINE(HAVE_LIBTOMCRYPT,1,[ ])
  PHP_NEW_EXTENSION(tomcrypt, tomcrypt.c, $ext_shared)
  PHP_SUBST(TOMCRYPT_SHARED_LIBADD)

  if test -n "$TOMCRYPT_LIBS"; then
    PHP_ADD_LIBRARY_WITH_PATH($TOMCRYPT_LIBS, $TOMCRYPT_LIBDIR, TOMCRYPT_SHARED_LIBADD)
  fi

  PHP_ADD_INCLUDE($TOMCRYPT_INCDIR)

fi
