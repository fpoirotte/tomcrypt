--TEST--
tomcrypt - RC5 cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        die "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_CIPHER_RC5, tomcrypt_list_ciphers())) {
        die "cipher not available";
    }
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_RC5;
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // Test vectors from https://www.cosic.esat.kuleuven.be/nessie/testvectors/
    $pt     = "\x42\x42\x42\x42\x42\x42\x42\x42";
    $key    = "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(8)
int(8)
int(128)
int(12)
string(16) "82151ff806a10919"
bool(true)

