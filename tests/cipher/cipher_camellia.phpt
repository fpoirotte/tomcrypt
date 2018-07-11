--TEST--
tomcrypt - Camellia cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_ECB, tomcrypt_list_modes())) {
        print "skip ECB mode not available";
    } elseif (!in_array(TOMCRYPT_CIPHER_CAMELLIA, tomcrypt_list_ciphers())) {
        print "skip cipher not available";
    } elseif (version_compare(LIBTOMCRYPT_VERSION_TEXT, '1.18', '<')) {
        // In LibTomCrypt <= 1.17, the implementation was broken.
        $hash = "45dcbc654d5867bb5ee475b9b1be0b2c3959d0de";
        print "skip Camellia is broken in this version of LibTomCrypt " .
            "(see https://github.com/libtom/libtomcrypt/commit/$hash)";
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_CAMELLIA;
    var_dump(
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
int(16)
int(16)
int(32)
int(18)
string(32) "42424242424242424242424242424242"
bool(true)

