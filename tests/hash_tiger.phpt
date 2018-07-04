--TEST--
tomcrypt - TIGER (192,3) hash
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_HASH_TIGER, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--FILE--
<?php
    $hash = TOMCRYPT_HASH_TIGER;
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
int(24)
string(48) "432b916300b93d2849bca4629ad04e6d8acff835aa42a8fa"
string(48) "432b916300b93d2849bca4629ad04e6d8acff835aa42a8fa"

