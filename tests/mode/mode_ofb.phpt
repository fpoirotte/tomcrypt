--TEST--
tomcrypt - OFB mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_OFB, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_NULL=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_OFB;
    $cipher = TOMCRYPT_CIPHER_NULL_REGULAR;
    $opts   = array(
        'iv' => '?',
    );
    $pt     = 'Test';
    $key    = '';
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, $mode, $opts);
    $exp    = ($opts['iv'] ^ $pt[0]) .
              ($opts['iv'] ^ $pt[1]) .
              ($opts['iv'] ^ $pt[2]) .
              ($opts['iv'] ^ $pt[3]);
    var_dump($ct === $exp);

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
bool(true)

