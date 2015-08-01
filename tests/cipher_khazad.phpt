--TEST--
tomcrypt - KHAZAD cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    if (!defined('TOMCRYPT_CIPHER_KHAZAD')) print "skip cipher not available";
    if (!defined('TOMCRYPT_MODE_ECB')) print "skip mode not available";
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_KHAZAD;
    var_dump(
        in_array($cipher, tomcrypt_list_ciphers()),
        tomcrypt_cipher_name($cipher),
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vectors from https://www.cosic.esat.kuleuven.be/nessie/testvectors/
    $pt     = "\x42\x42\x42\x42\x42\x42\x42\x42";
    $key    = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
string(6) "khazad"
int(8)
int(16)
int(16)
int(8)
string(16) "f2398bab23277fb9"
bool(true)

