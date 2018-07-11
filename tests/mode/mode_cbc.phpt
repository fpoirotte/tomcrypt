--TEST--
tomcrypt - CBC mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_CBC, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_NULL=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_CBC;
    $cipher = TOMCRYPT_CIPHER_NULL_FAST;
    $opts   = array(
        'iv' => '????????',
    );
    $pt     = 'Testtest';
    $key    = '';
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, $mode, $opts);
    $exp    = $opts['iv'] ^ $pt;
    var_dump($ct === $exp);

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
bool(true)

