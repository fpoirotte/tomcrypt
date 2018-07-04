--TEST--
tomcrypt - SHA2 (384) hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_SHA2_384, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_SHA2_384;
    $data = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'hello.bin');
    var_dump(
        tomcrypt_hash_block_size($hash),
        tomcrypt_hash_digest_size($hash),
        tomcrypt_hash_string($hash, $data, false),
        tomcrypt_hash_file($hash, __DIR__ . DIRECTORY_SEPARATOR . 'hello.bin', false)
    );
?>
--EXPECT--
int(128)
int(48)
string(96) "86255fa2c36e4b30969eae17dc34c772cbebdfc58b58403900be87614eb1a34b8780263f255eb5e65ca9bbb8641cccfe"
string(96) "86255fa2c36e4b30969eae17dc34c772cbebdfc58b58403900be87614eb1a34b8780263f255eb5e65ca9bbb8641cccfe"

