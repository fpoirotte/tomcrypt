--TEST--
tomcrypt - Camellia cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_CAMELLIA;
    var_dump(
        in_array($cipher, tomcrypt_list_ciphers()),
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vector from https://www.cosic.esat.kuleuven.be/nessie/testvectors/
    // This is set 7, vector #66 in direct key mode
    $pt     = "\x69\x93\xEE\x35\xDB\x15\x29\x65\x0A\xD7\x7A\x9E\xF5\xB6\xDC\xCC";
    $key    = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
int(16)
int(16)
int(32)
int(18)
string(32) "42424242424242424242424242424242"
bool(true)

