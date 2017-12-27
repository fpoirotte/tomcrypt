--TEST--
tomcrypt - MULTI2 cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    elseif (version_compare(LIBTOMCRYPT_VERSION_TEXT, '1.18', '<')) {
        // In LibTomCrypt <= 1.17, the implementation was broken.
        $hash = "21ddcf35681916c091ae91e7e8e5bd6bdf8ab51d";
        print "Multi2 is broken in this version of LibTomCrypt " .
               "(see https://github.com/libtom/libtomcrypt/commit/$hash)"
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_MULTI2;
    var_dump(
        in_array($cipher, tomcrypt_list_ciphers()),
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    $pt     = "\x00\x00\x00\x00\x00\x00\x00\x01";
    // $key = $systemKey . $dataKey
    $key    = str_repeat("\x00", 32) . "\x01\x23\x45\x67\x89\xAB\xCD\xEF";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
int(8)
int(40)
int(40)
int(128)
string(16) "f89440845e11cf89"
bool(true)

