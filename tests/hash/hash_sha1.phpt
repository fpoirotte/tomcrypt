--TEST--
tomcrypt - SHA-1 hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_SHA1, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_SHA1;
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
int(20)
string(40) "d3486ae9136e7856bc42212385ea797094475802"
string(40) "d3486ae9136e7856bc42212385ea797094475802"

