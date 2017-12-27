--TEST--
tomcrypt - SAFERK64 cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_CIPHER_SAFERK64, tomcrypt_list_ciphers())) {
        print "skip cipher not available";
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_SAFERK64;
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vectors from Handbook of Applied Cryptography
    // by Alfred J. Menezes, Paul C. van Oorschot, Scott A. Vanstone
    $pt     = "\x01\x02\x03\x04\x05\x06\x07\x08";
    $key    = "\x08\x07\x06\x05\x04\x03\x02\x01";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(8)
int(8)
int(8)
int(6)
string(16) "c8f29cdd87783ed9"
bool(true)

