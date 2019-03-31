--TEST--
tomcrypt - F8 mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_F8, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_TESTS=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_F8;
    // In fast mode, the cipher's block size must be a multiple
    // of the machine's word size. This should be OK.
    $cipher = TOMCRYPT_CIPHER_NULL_128;
    $opts   = array(
        'iv' => '?',
    );
    $pt     = 'Test';
    $key    = '';
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, $mode, $opts);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
