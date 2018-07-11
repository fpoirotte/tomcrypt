--TEST--
tomcrypt - Yarrow PRNG
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_RNG_YARROW, tomcrypt_list_rngs())){
        print "skip RNG not available";
    }
?>
--FILE--
<?php
    $rng = TOMCRYPT_RNG_YARROW;

    $rand0 = tomcrypt_rng_get_bytes(8, $rng);
    $state = tomcrypt_rng_export($rng);

    var_dump(tomcrypt_rng_import($rng, $state));
    $rand1 = tomcrypt_rng_get_bytes(8, $rng);
    var_dump(tomcrypt_rng_import($rng, $state));
    $rand2 = tomcrypt_rng_get_bytes(8, $rng);

    var_dump($rand0 == $rand1);
    var_dump($rand1 == $rand2);
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(true)

