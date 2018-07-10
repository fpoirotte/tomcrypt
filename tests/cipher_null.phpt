--TEST--
tomcrypt - NULL cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_ECB, tomcrypt_list_modes())) {
        print "skip ECB mode not available";
    }
?>
--FILE--
<?php
    $cipher = "null"; // Secret cipher :)
    var_dump(
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    // The null cipher does not encrypt anything
    // and does not require blocksize alignment.
    $pt     = "Test";
    $key    = "";
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
int(1)
int(0)
int(0)
int(1)
string(8) "54657374"
bool(true)

