--TEST--
tomcrypt - DES cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_ECB, tomcrypt_list_modes())) {
        print "skip ECB mode not available";
    } elseif (!in_array(TOMCRYPT_CIPHER_DES, tomcrypt_list_ciphers())) {
        print "skip cipher not available";
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_DES;
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    $pt     = 'Hi, hello world!';
    $key    = 'a secret';
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(8)
int(8)
int(8)
int(16)
string(32) "a86bd6cecd024a40f8f1d7934d2f1f78"
bool(true)

