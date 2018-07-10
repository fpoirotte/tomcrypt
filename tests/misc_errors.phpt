--TEST--
tomcrypt - Errors
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
?>
--FILE--
<?php
    var_dump(
        tomcrypt_errno(),
        tomcrypt_error(),
        tomcrypt_error(0),
        tomcrypt_error(1)
    );

    @tomcrypt_hash_block_size('non-existing-hash');
    var_dump(
        tomcrypt_errno(),
        tomcrypt_error()
    );

    tomcrypt_clear();
    var_dump(
        tomcrypt_errno(),
        tomcrypt_error()
    );
?>
--EXPECT--
int(0)
string(8) "CRYPT_OK"
string(8) "CRYPT_OK"
string(11) "CRYPT_ERROR"
int(16)
string(26) "Invalid argument provided."
int(0)
string(8) "CRYPT_OK"

