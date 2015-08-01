php_tomcrypt
============

PHP bindings for `libtomcrypt <http://www.libtom.net/>`.

Badges: |badge-travis|

Why?
----
I made this extension for two reasons:

*   First, I wanted to learn how to write a PHP extension.

*   Secondly, there has been discussion recently on the ``php.internals``
    mailing list to remove the bundled ``mcrypt`` extension from PHP 7.0+.

    While I agree with the rationale behind that discussion (libmcrypt
    seems to have been abandoned since a few years), I also needed a
    replacement for some of my own projects. Therefore, I decided to
    look for a crypto library with:

    *   a permissive license (see below)

    *   a simple API so that I could easily write bindings for it
        (I didn't want to have to learn OpenSSL's API for example)

    *   relatively good support (eg. widely packaged, receiving
        updates, etc.)

Installation
------------
You can install this extension using ``pear``:

..  sourcecode:: console

    pear install https://github.com/fpoirotte/tomcrypt/archive/master.tar.gz

It will also try to add the extension to your ``php.ini`` automatically.
If it fails to do so, you can enable the extension manually by adding
the following line to your ``php.ini``:

..  sourcecode:: ini

    extension=tomcrypt.so

Windows support
---------------
The extension should compile and run just fine under Windows.
Unfortunately, I do not have access to Windows development tools
and cannot compile a binary release for Windows users.

If you manage to compile the extension on Windows, please let me know through
`GitHub's issue tracker <https://github.com/fpoirotte/tomcrypt/issues>`.

License
-------
libtomcrypt is released under the `WTFPL <http://sam.zoy.org/wtfpl/>` license.

php_tomcrypt is released under version 3.01 of the
`PHP <http://www.php.net/license/3_01.txt>` license.

..  |badges-travis| image:: https://travis-ci.org/fpoirotte/tomcrypt.svg
    :alt: Travis-CI (unknown)
    :target: http://travis-ci.org/fpoirotte/tomcrypt
