--TEST--
tomcrypt - MD4 hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_MD4, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_MD4;
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
int(16)
string(32) "0d7a9db5a3bed4ae5738ee6d1909649c"
string(32) "0d7a9db5a3bed4ae5738ee6d1909649c"
