--TEST--
tomcrypt - SHA3 (512) hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_SHA3_512, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_SHA3_512;
    $data = file_get_contents(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'hello.bin');
    var_dump(
        tomcrypt_hash_block_size($hash),
        tomcrypt_hash_digest_size($hash),
        tomcrypt_hash_string($hash, $data, false),
        tomcrypt_hash_file($hash, dirname(__DIR__) . DIRECTORY_SEPARATOR . 'hello.bin', false)
    );
?>
--EXPECT--
int(72)
int(64)
string(128) "95decc72f0a50ae4d9d5378e1b2252587cfc71977e43292c8f1b84648248509f1bc18bc6f0b0d0b8606a643eff61d611ae84e6fbd4a2683165706bd6fd48b334"
string(128) "95decc72f0a50ae4d9d5378e1b2252587cfc71977e43292c8f1b84648248509f1bc18bc6f0b0d0b8606a643eff61d611ae84e6fbd4a2683165706bd6fd48b334"

