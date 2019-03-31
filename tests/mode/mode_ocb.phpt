--TEST--
tomcrypt - OCB mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_OCB, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_TESTS=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_OCB;
    $cipher = TOMCRYPT_CIPHER_TEST_AES;

    // Last test vector from RFC 7253
    list($K, $N, $A, $P, $C, $T) =  array(
        '0f0e0d0c0b0a09080706050403020100',
        'BBAA9988776655443322110D',
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
        '1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6A',
        'D0C515F4D1CDD4FDAC4F02AA',
    );

    $opts   = array(
        'nonce'     => pack('H*', $N),
        'authdata'  => pack('H*', $A),
    );
    $pt     = pack('H*', $P);
    $key    = pack('H*', $K);
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, $mode, $opts);
    var_dump($ct == strtolower($C));
    var_dump($opts['tag'] == strtolower($T));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts);
    var_dump($pt === $pt2);

    $tag = $opts['tag'];
    unset($opts['tag']);
    var_dump(tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts));

    $opts['tag'] = $tag;
    unset($opts['authdata']);
    var_dump(tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)

Warning: tomcrypt_cipher_decrypt(): Tag verification failed in %s on line %d
bool(false)

Warning: tomcrypt_cipher_decrypt(): Tag verification failed in %s on line %d
bool(false)

