php_tomcrypt
============

PHP bindings for `libtomcrypt <http://www.libtom.net/>`.

Badges: |badge-travis|

Why?
----
I made this extension for two reasons:

*   First, I wanted to learn how to write a PHP extension.

*   The ``mcrypt`` extension was deprecated in PHP 7.0-7.1 and it has been
    completely removed from PHP 7.2.

    While I agree with the rationale behind that decision
    (libmcrypt has not been maintained since 2007), I also needed a
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

    wget https://github.com/fpoirotte/tomcrypt/archive/master.tar.gz
    tar zxvf master.tar.gz
    pear install tomcrypt-master/package.xml

It will also try to add the extension to your ``php.ini`` automatically.
If it fails to do so, you can enable the extension manually by adding
the following line to your ``php.ini``:

..  sourcecode:: ini

    extension=tomcrypt.so

Usage
-----

Encryption
~~~~~~~~~~

Use code such as the following to encrypt some plaintext data:

..  sourcecode:: php

    <?php
        $algo       = TOMCRYPT_CIPHER_RIJNDAEL;
        $mode       = TOMCRYPT_MODE_ECB;
        $plaintext  = "Confidential msg";
        $key        = "some secret key!";
        $ciphertext = tomcrypt_cipher_encrypt($algo, $key, $plaintext, $mode);
    ?>

The list of supported ciphers for your platform can be obtained through ``tomcrypt_list_ciphers()``.
This extension also provides constants which can be used to refer to the various ciphers:

*   ``TOMCRYPT_CIPHER_3DES``
*   ``TOMCRYPT_CIPHER_AES``
*   ``TOMCRYPT_CIPHER_ANUBIS``
*   ``TOMCRYPT_CIPHER_BLOWFISH``
*   ``TOMCRYPT_CIPHER_CAMELLIA``
*   ``TOMCRYPT_CIPHER_CAST5``
*   ``TOMCRYPT_CIPHER_DES``
*   ``TOMCRYPT_CIPHER_KASUMI``
*   ``TOMCRYPT_CIPHER_KHAZAD``
*   ``TOMCRYPT_CIPHER_MULTI2``
*   ``TOMCRYPT_CIPHER_NOEKEON``
*   ``TOMCRYPT_CIPHER_RC2``
*   ``TOMCRYPT_CIPHER_RC5``
*   ``TOMCRYPT_CIPHER_RC6``
*   ``TOMCRYPT_CIPHER_RIJNDAEL``
*   ``TOMCRYPT_CIPHER_SAFER128``
*   ``TOMCRYPT_CIPHER_SAFER64``
*   ``TOMCRYPT_CIPHER_SAFERK128``
*   ``TOMCRYPT_CIPHER_SAFERK64``
*   ``TOMCRYPT_CIPHER_SAFERPLUS``
*   ``TOMCRYPT_CIPHER_SAFERSK128``
*   ``TOMCRYPT_CIPHER_SAFERSK64``
*   ``TOMCRYPT_CIPHER_SEED``
*   ``TOMCRYPT_CIPHER_SKIPJACK``
*   ``TOMCRYPT_CIPHER_TRIPLEDES``
*   ``TOMCRYPT_CIPHER_TWOFISH``
*   ``TOMCRYPT_CIPHER_XTEA``

The list of supported encryption/decryption modes can be retrieved through ``tomcrypt_list_modes()``.
The following constants are also provided:

* ``TOMCRYPT_MODE_CBC``
* ``TOMCRYPT_MODE_CCM``
* ``TOMCRYPT_MODE_CFB``
* ``TOMCRYPT_MODE_CHACHA20POLY1305``
* ``TOMCRYPT_MODE_CTR``
* ``TOMCRYPT_MODE_EAX``
* ``TOMCRYPT_MODE_ECB``
* ``TOMCRYPT_MODE_F8``
* ``TOMCRYPT_MODE_GCM``
* ``TOMCRYPT_MODE_LRW``
* ``TOMCRYPT_MODE_OCB``
* ``TOMCRYPT_MODE_OCB3``
* ``TOMCRYPT_MODE_OFB``
* ``TOMCRYPT_MODE_XTS``


Decryption
~~~~~~~~~~

Decryption works pretty much the same way encryption does:

..  sourcecode:: php

    <?php
        $algo       = TOMCRYPT_CIPHER_RIJNDAEL;
        $mode       = TOMCRYPT_MODE_ECB;
        $key        = "some secret key!";
        $plaintext  = tomcrypt_cipher_decrypt($algo, $key, $ciphertext, $mode);
    ?>

Of course, for decryption to work properly, the same algorithm (cipher), mode
and secret key should be used during encryption and decryption.


Hashing
~~~~~~~

Hashing data can easily be done using the following code:

..  sourcecode:: php

    <?php
        $algo = TOMCRYPT_HASH_SHA256;

        // Returns the hash value for the given data in hexadecimal form
        $hash = tomcrypt_hash_string($algo, $data, false);

        // Returns the hash value for the given data in raw (binary) form
        $hash = tomcrypt_hash_string($algo, $data, true);

        // Returns the hash value for the given file in raw (binary) form
        $hash = tomcrypt_hash_file($algo, "/tmp/file", true);
    ?>

Use ``tomcrypt_list_hashes()`` to get a list of supported hashing algorithms.
Like with ciphers, several constants are provided to refer to the various
known hashing algorithms:

*   ``TOMCRYPT_HASH_BLAKE2B_160``
*   ``TOMCRYPT_HASH_BLAKE2B_256``
*   ``TOMCRYPT_HASH_BLAKE2B_384``
*   ``TOMCRYPT_HASH_BLAKE2B_512``
*   ``TOMCRYPT_HASH_BLAKE2S_128``
*   ``TOMCRYPT_HASH_BLAKE2S_160``
*   ``TOMCRYPT_HASH_BLAKE2S_224``
*   ``TOMCRYPT_HASH_BLAKE2S_256``
*   ``TOMCRYPT_HASH_MD2``
*   ``TOMCRYPT_HASH_MD4``
*   ``TOMCRYPT_HASH_MD5``
*   ``TOMCRYPT_HASH_RIPEMD128``
*   ``TOMCRYPT_HASH_RIPEMD160``
*   ``TOMCRYPT_HASH_RIPEMD256``
*   ``TOMCRYPT_HASH_RIPEMD320``
*   ``TOMCRYPT_HASH_SHA1``
*   ``TOMCRYPT_HASH_SHA256``
*   ``TOMCRYPT_HASH_SHA384``
*   ``TOMCRYPT_HASH_SHA512``
*   ``TOMCRYPT_HASH_TIGER``
*   ``TOMCRYPT_HASH_WHIRLPOOL``


Message Authentication Codes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generating a Message Authentication Code (MAC) can be done
using the following code:

..  sourcecode:: php

    <?php
        $algo1  = TOMCRYPT_MAC_HMAC;
        $hash   = TOMCRYPT_HASH_SHA1;
        $key    = "my secret key...";
        $data   = "some data here";

        // Returns the HMAC for the given data in hexadecimal form,
        // using the SHA-1 hashing algorithm.
        $hmac   = tomcrypt_mac_string($algo1, $hash, $key, $data, false);

        // Returns the PMAC for the given data in raw (binary) form,
        // using the Rijndael cipher algorithm.
        $algo2  = TOMCRYPT_MAC_PMAC;
        $cipher = TOMCRYPT_CIPHER_RIJNDAEL;
        $pmac   = tomcrypt_mac_string($algo2, $cipher, $key, $data, true);

        // Returns the HMAC for the given file in raw (binary) form,
        // using the SHA-1 hashing algorithm.
        $hmac   = tomcrypt_mac_file($algo1, $hash, $key, "/tmp/file", true);
    ?>

Use ``tomcrypt_list_macs()`` for a list of MAC algorithms supported by your
platform. The following constants are also provided:

*   ``TOMCRYPT_MAC_BLAKE2B``
*   ``TOMCRYPT_MAC_BLAKE2S``
*   ``TOMCRYPT_MAC_CMAC``
*   ``TOMCRYPT_MAC_F9``
*   ``TOMCRYPT_MAC_HMAC``
*   ``TOMCRYPT_MAC_PELICAN``
*   ``TOMCRYPT_MAC_PMAC``
*   ``TOMCRYPT_MAC_POLY1305``
*   ``TOMCRYPT_MAC_XCBC``

Most of these MAC algorithms require an additional algorithm to be given:

*   ``TOMCRYPT_MAC_BLAKE2B``, ``TOMCRYPT_MAC_BLAKE2S`` and
    ``TOMCRYPT_MAC_POLY1305``: no additional algorithm is necessary
    (i.e. you may pass ``null`` instead of an algorithm)
*   ``TOMCRYPT_MAC_HMAC``: some hashing algorithm must be passed
*   other MAC algorithms: a cipher must be passed

Please refer to the documentation on `Encryption`_ and `Hashing`_ for more
information about supported algorithms.


(Pseudo-)Random Number Generators
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This extension can provide you with data generated at random, as an alternative
to `openssl_random_pseudo_bytes() <http://php.net/openssl_random_pseudo_bytes>`.

The following code can be used to generate (pseudo-)random number generators:

..  sourcecode:: php

    <?php
        // Attempt to get 42 bytes of purely random data.
        // Returns FALSE if random data cannot be obtained in a secure way.
        $random = tomcrypt_rng_get_bytes(42, TOMCRYPT_RNG_SECURE);
    ?>

Various algorithms of (pseudo-)random number generators are available:

*   ``TOMCRYPT_RNG_CHACHA20``
*   ``TOMCRYPT_RNG_FORTUNA``
*   ``TOMCRYPT_RNG_RC4``
*   ``TOMCRYPT_RNG_SECURE``
*   ``TOMCRYPT_RNG_SOBER128``
*   ``TOMCRYPT_RNG_YARROW``

..  warning::

    Apart from ``TOMCRYPT_RNG_SECURE`` --- which is the default RNG used by
    ``tomcrypt_rng_get_bytes()``, all the other generators are only PRNGs
    and should not be used when truly random data is required.


Windows support
---------------
The extension should compile and run just fine under Windows.
Unfortunately, I do not have access to Windows development tools
and cannot compile a binary release for Windows users.

If you manage to compile the extension on Windows, please let us know through
`our issue tracker <https://github.com/fpoirotte/tomcrypt/issues>`.

License
-------
libtomcrypt is released under the `WTFPL <http://sam.zoy.org/wtfpl/>` license.

php_tomcrypt is released under version 3.01 of the
`PHP <http://www.php.net/license/3_01.txt>` license.

..  |badges-travis| image:: https://travis-ci.org/fpoirotte/tomcrypt.svg
    :alt: Travis-CI (unknown)
    :target: http://travis-ci.org/fpoirotte/tomcrypt

..  |---| unicode:: U+02014 .. em dash
    :trim:
