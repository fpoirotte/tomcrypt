--TEST--
tomcrypt - RIPEMD256 hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_RIPEMD256, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_RIPEMD256;
    $data = file_get_contents(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'hello.bin');
    var_dump(
        tomcrypt_hash_block_size($hash),
        tomcrypt_hash_digest_size($hash),
        tomcrypt_hash_string($hash, $data, false),
        tomcrypt_hash_file($hash, dirname(__DIR__) . DIRECTORY_SEPARATOR . 'hello.bin', false)
    );
?>
--EXPECT--
int(64)
int(32)
string(64) "2700f1122c7bd5df165b0615efbbbc54f551aef2401738811a5aea19ccb9233a"
string(64) "2700f1122c7bd5df165b0615efbbbc54f551aef2401738811a5aea19ccb9233a"

