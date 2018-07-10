PHP_ARG_WITH(tomcrypt, for LibTomCrypt support,
[  --with-tomcrypt[=DIR]    Include LibTomCrypt support])

if test "$PHP_TOMCRYPT" != "no"; then
  SEARCH_PATH="/usr/local /usr"
  SEARCH_FOR="/include/tomcrypt.h"

  AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  AC_MSG_CHECKING([for LibTomCrypt])

  dnl user-provided location
  if test -r $PHP_TOMCRYPT/$SEARCH_FOR; then
    LIBTOMCRYPT_INCDIR=$PHP_TOMCRYPT/include
    LIBTOMCRYPT_LIBDIR=$PHP_TOMCRYPT/$PHP_LIBDIR
    AC_MSG_RESULT([found in $PHP_TOMCRYPT])

  dnl pkg-config output
  elif test -x "$PKG_CONFIG" && $PKG_CONFIG --exists libtomcrypt; then
    LIBTOMCRYPT_VERSION=`$PKG_CONFIG libtomcrypt --modversion`
    if $PKG_CONFIG libtomcrypt --atleast-version=1.15; then
      LIBTOMCRYPT_INCDIR=`$PKG_CONFIG libtomcrypt --variable=includedir`
      LIBTOMCRYPT_LIBDIR=`$PKG_CONFIG libtomcrypt --variable=libdir`
      AC_MSG_RESULT(version $LIBTOMCRYPT_VERSION found using pkg-config)
      PHP_EVAL_LIBLINE($LIBTOMCRYPT_LIBDIR, TOMCRYPT_SHARED_LIBADD)
      PHP_EVAL_INCLINE($LIBTOMCRYPT_INCDIR)
    else
      AC_MSG_ERROR([LibTomCrypt $LIBTOMCRYPT_VERSION is too old, version >= 1.15 required])
    fi

  else
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        LIBTOMCRYPT_INCDIR=$i/include
        LIBTOMCRYPT_LIBDIR=$i/$PHP_LIBDIR
        AC_MSG_RESULT(found in $i)
      fi
    done
    if test -z "$LIBTOMCRYPT_INCDIR"; then
      AC_MSG_ERROR([Please install LibTomCrypt - See https://github.com/libtom/libtomcrypt])
    fi
  fi

  LIBNAME=tomcrypt
  LIBSYMBOL=crypt_fsa

  if test -n "$LIBTOMCRYPT_INCDIR"; then
    PHP_ADD_INCLUDE($LIBTOMCRYPT_INCDIR)
  fi
  if test -n "$LIBTOMCRYPT_LIBDIR"; then
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $LIBTOMCRYPT_LIBDIR, TOMCRYPT_SHARED_LIBADD)
  fi

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    AC_DEFINE(HAVE_LIBTOMCRYPT,1,[ ])
  ],[
    AC_MSG_ERROR([LibTomCrypt not found or too old (< 1.15)])
  ],[
  ])

  PHP_SUBST(TOMCRYPT_SHARED_LIBADD)
  EXT_TOMCRYPT_SOURCES=$(cd src/ && echo src/*.c src/modes/*.c src/ciphers/*.c)
  PHP_NEW_EXTENSION(tomcrypt, $EXT_TOMCRYPT_SOURCES, $ext_shared)
fi
