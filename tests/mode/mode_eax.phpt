--TEST--
tomcrypt - EAX mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_EAX, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_TESTS=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_EAX;
    $cipher = TOMCRYPT_CIPHER_TEST_AES;

    // Last test vector from https://cseweb.ucsd.edu/~mihir/papers/eax.html
    list($P, $K, $N, $A, $C, $T) =  array(
        'CA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7',
        '8395FCF1E95BEBD697BD010BC766AAC3',
        '22E7ADD93CFC6393C57EC0B3C17D6B44',
        '126735FCC320D25A',
        'CB8920F87A6C75CFF39627B56E3ED197C552D295A7',
        'CFC46AFC253B4652B1AF3795B124AB6E',
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

