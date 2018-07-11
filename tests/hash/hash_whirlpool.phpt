--TEST--
tomcrypt - WHIRLPOOL hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_WHIRLPOOL, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_WHIRLPOOL;
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
int(64)
string(128) "bb4f1451ec1b8326643d25d74547591619cb01dd1f104d729a13494cbd95382d3526b00a2d3fdf448e1e4b39887c54fe2aea9767872b58ed361eb3a12075c5b5"
string(128) "bb4f1451ec1b8326643d25d74547591619cb01dd1f104d729a13494cbd95382d3526b00a2d3fdf448e1e4b39887c54fe2aea9767872b58ed361eb3a12075c5b5"

