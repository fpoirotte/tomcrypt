--TEST--
tomcrypt - SAFER128 cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        die "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_CIPHER_SAFERSK128, tomcrypt_list_ciphers())) {
        die "cipher not available";
    }
?>
--XFAIL--
No access to alternative implementation for test vector comparison
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_SAFERSK128;
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    $pt     = 'Hi, hello world!';
    $key    = 'something secret';
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(8)
int(8)
int(56)
int(16)
string(32) "af1e06dcdc8d7c198e19e7850bccc71c"
bool(true)

