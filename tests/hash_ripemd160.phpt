--TEST--
tomcrypt - RIPEMD160 hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_RIPEMD160, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_RIPEMD160;
    $data = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'hello.bin');
    var_dump(
        tomcrypt_hash_block_size($hash),
        tomcrypt_hash_digest_size($hash),
        tomcrypt_hash_string($hash, $data, false),
        tomcrypt_hash_file($hash, __DIR__ . DIRECTORY_SEPARATOR . 'hello.bin', false)
    );
?>
--EXPECT--
int(64)
int(20)
string(40) "7f772647d88750add82d8e1a7a3e5c0902a346a3"
string(40) "7f772647d88750add82d8e1a7a3e5c0902a346a3"

