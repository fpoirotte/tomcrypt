--TEST--
tomcrypt - RC4 cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    if (!defined('TOMCRYPT_CIPHER_RC4')) print "skip cipher not available";
    if (!defined('TOMCRYPT_MODE_ECB')) print "skip mode not available";
?>
--XFAIL--
this extension's implementation does not match the specifications for now
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_RC4;
    var_dump(
        in_array($cipher, tomcrypt_list_ciphers()),
        tomcrypt_cipher_name($cipher),
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vectors generated with openssl
    $pt     = "something secret";
    $key    = "abcde";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
string(3) "rc4"
int(1)
int(1)
int(256)
int(1)
string(16) "9a0d9f11584393f5b6448443801dbd96"
bool(true)

