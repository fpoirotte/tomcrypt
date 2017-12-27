--TEST--
tomcrypt - XTEA cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_CIPHER_XTEA, tomcrypt_list_ciphers())) {
        print "skip cipher not available";
    } elseif (version_compare(LIBTOMCRYPT_VERSION_TEXT, '1.18', '<')) {
        // In LibTomCrypt <= 1.17, the implementation was broken.
        $hash = "2526d5df8f9a228cf20ba90982aed4a5e951ac5f";
        print "skip XTEA is broken in this version of LibTomCrypt " .
            "(see https://github.com/libtom/libtomcrypt/commit/$hash)"
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_XTEA;
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vector from http://forums.phpfreaks.com/topic/262043-xtea/?p=1342856
    $pt     = "\x41\x41\x41\x41\x41\x41\x41\x41";
    $key    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(8)
int(16)
int(16)
int(32)
string(16) "ed23375a821a8c2d"
bool(true)

