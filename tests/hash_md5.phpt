--TEST--
tomcrypt - MD5 hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_MD5, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_MD5;
    $data = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'hello.bin');
    var_dump(
        tomcrypt_hash_block_size($hash),
        tomcrypt_hash_digest_size($hash),
        tomcrypt_hash_string($hash, $data, false),
        tomcrypt_hash_file($hash, __DIR__ . DIRECTORY_SEPARATOR . 'hello.bin', false),
        md5($data)
    );
?>
--EXPECT--
int(64)
int(16)
string(32) "86fb269d190d2c85f6e0468ceca42a20"
string(32) "86fb269d190d2c85f6e0468ceca42a20"
string(32) "86fb269d190d2c85f6e0468ceca42a20"

