--TEST--
tomcrypt - SHA3 (256) hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_SHA3_256, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_SHA3_256;
    $data = file_get_contents(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'hello.bin');
    var_dump(
        tomcrypt_hash_block_size($hash),
        tomcrypt_hash_digest_size($hash),
        tomcrypt_hash_string($hash, $data, false),
        tomcrypt_hash_file($hash, dirname(__DIR__) . DIRECTORY_SEPARATOR . 'hello.bin', false)
    );
?>
--EXPECT--
int(136)
int(32)
string(64) "d6ea8f9a1f22e1298e5a9506bd066f23cc56001f5d36582344a628649df53ae8"
string(64) "d6ea8f9a1f22e1298e5a9506bd066f23cc56001f5d36582344a628649df53ae8"

