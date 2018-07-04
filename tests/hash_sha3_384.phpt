--TEST--
tomcrypt - SHA3 (384) hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_SHA3_384, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_SHA3_384;
    $data = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'hello.bin');
    var_dump(
        tomcrypt_hash_block_size($hash),
        tomcrypt_hash_digest_size($hash),
        tomcrypt_hash_string($hash, $data, false),
        tomcrypt_hash_file($hash, __DIR__ . DIRECTORY_SEPARATOR . 'hello.bin', false)
    );
?>
--EXPECT--
int(104)
int(48)
string(96) "f9210511d0b2862bdcb672daa3f6a4284576ccb24d5b293b366b39c24c41a6918464035ec4466b12e22056bf559c7a49"
string(96) "f9210511d0b2862bdcb672daa3f6a4284576ccb24d5b293b366b39c24c41a6918464035ec4466b12e22056bf559c7a49"

