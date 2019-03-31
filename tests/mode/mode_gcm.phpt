--TEST--
tomcrypt - GCM mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_GCM, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_TESTS=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_GCM;
    $cipher = TOMCRYPT_CIPHER_TEST_AES;

    // Last test case from "The Galois/Counter Mode of Operation (GCM)"
    // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
    list($K, $P, $A, $N, $C, $T) = array(
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' .
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
        'feedfacedeadbeeffeedfacedeadbeefabaddad2',
        '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728' .
        'c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
        '5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4' .
        '0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f',
        'a44a8266ee1c8eb0c8b5d4cf5ae9f19a',
    );

    $opts   = array(
        'iv'        => pack('H*', $N),
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

