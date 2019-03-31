--TEST--
tomcrypt - CTR mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_CTR, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--ENV--
PLTC_TESTS=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_CTR;
    $cipher = TOMCRYPT_CIPHER_TEST_AES;

    // Test vector from NIST SP 800-38A (F.5.1 CTR-AES128.Encrypt)
    list($K, $Ctr, $P, $C) = array(
        '2b7e151628aed2a6abf7158809cf4f3c',
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
        '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51' .
        '30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
        '874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff' .
        '5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee',
    );

    $opts   = array(
        'iv'        => pack('H*', $Ctr),
        'ctr_mode'  => TOMCRYPT_CTR_BIG_ENDIAN,
    );
    $pt     = pack('H*', $P);
    $key    = pack('H*', $K);
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, $mode, $opts);
    var_dump(bin2hex($ct) == strtolower($C));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
bool(true)
