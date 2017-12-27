--TEST--
tomcrypt - CAST5 cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        die "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_CIPHER_CAST5, tomcrypt_list_ciphers())) {
        die "cipher not available";
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_CAST5;
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
int(5)
int(16)
int(16)
string(32) "b5efaa3e36aeae77ae49635b38ef2cec"
bool(true)

