--TEST--
tomcrypt - XTEA cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    if (!defined('TOMCRYPT_CIPHER_XTEA')) print "skip cipher not available";
    if (!defined('TOMCRYPT_MODE_ECB')) print "skip mode not available";
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_XTEA;
    var_dump(
        in_array($cipher, tomcrypt_list_ciphers()),
        tomcrypt_cipher_name($cipher),
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vectors from http://forums.phpfreaks.com/topic/262043-xtea-encryptiondecryption/?p=1342856
    // Note: libtomcrypt uses native-endianness while the above uses big-endian.
    $pt     = "\x41\x41\x41\x41\x41\x41\x41\x41";
    $key    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
string(4) "xtea"
int(8)
int(16)
int(16)
int(32)
string(16) "5a3723ed2d8c1a82"
bool(true)

