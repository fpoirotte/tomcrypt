--TEST--
tomcrypt - SAFERPLUS cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_ECB, tomcrypt_list_modes())) {
        print "skip ECB mode not available";
    } elseif (!in_array(TOMCRYPT_CIPHER_SAFERPLUS, tomcrypt_list_ciphers())) {
        print "skip cipher not available";
    }
?>
--XFAIL--
libtomcrypt's implementation does not seem to match specifications
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_SAFERPLUS;
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
int(16)
int(16)
int(32)
int(8)
string(32) "b79de3bf2c061291cdd35f27a45045ba"
bool(true)

