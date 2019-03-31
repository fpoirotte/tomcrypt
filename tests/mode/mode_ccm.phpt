--TEST--
tomcrypt - CCM mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_CCM, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_TESTS=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_CCM;
    $cipher = TOMCRYPT_CIPHER_TEST_AES;

    // First test vector from RFC 3610
    list($K, $N, $A, $P, $C, $T) = array(
        'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF',
        '00000003020100A0A1A2A3A4A5',
        '0001020304050607',
        '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E',
        '588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384',
        '17E8D12CFDF926E0',
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

