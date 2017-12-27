--TEST--
tomcrypt - NOEKEON cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_CIPHER_NOEKEON, tomcrypt_list_ciphers())) {
        print "skip cipher not available";
    } elseif (version_compare(LIBTOMCRYPT_VERSION_TEXT, '1.18', '<')) {
        // In LibTomCrypt <= 1.17, the implementation was broken.
        $hash = "6dc089015adfc4f66679b6b680476422bd6b6c01";
        print "skip Noekeon is broken in this version of LibTomCrypt " .
            "(see https://github.com/libtom/libtomcrypt/commit/$hash)";
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_NOEKEON;
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vector from https://www.cosic.esat.kuleuven.be/nessie/testvectors/
    // This is set 7, vector #66 in direct key mode
    $pt     = "\x3D\xF7\x87\x67\xE7\x84\x9B\x39\xD2\xD7\x66\x7D\xE9\x13\xD5\xE1";
    $key    = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(16)
int(16)
int(16)
int(16)
string(32) "42424242424242424242424242424242"
bool(true)

