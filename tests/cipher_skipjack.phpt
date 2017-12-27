--TEST--
tomcrypt - SKIPJACK cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_CIPHER_SKIPJACK, tomcrypt_list_ciphers())) {
        print "skip cipher not available";
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_SKIPJACK;
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // See http://csrc.nist.gov/publications/nistpubs/800-17/800-17.pdf
    // Note: libtomcrypt assumes little-endian values.
    $pt     = "\x80\x00\x00\x00\x00\x00\x00\x00";
    $key    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(8)
int(10)
int(10)
int(32)
string(16) "d7e30b5b8d2218d5"
bool(true)

