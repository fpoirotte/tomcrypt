--TEST--
tomcrypt - HMAC mac
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MAC_HMAC, tomcrypt_list_macs())) {
        print "skip mac not available";
    } elseif (!in_array(TOMCRYPT_HASH_SHA1, tomcrypt_list_hashes())) {
        print "skip hash not available";
    }
?>
--XFAIL--
No access to alternative implementation for test vector comparison
--FILE--
<?php
    $mac  = TOMCRYPT_MAC_HMAC;
    $sub  = TOMCRYPT_HASH_SHA1;
    $key  = 'something secret';
    $data = file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . 'hello.bin');

    var_dump(
        tomcrypt_mac_string($mac, $sub, $key, $data, false),
        tomcrypt_mac_file($mac, $sub, $key, __DIR__ . DIRECTORY_SEPARATOR . 'hello.bin', false),
        bin2hex(tomcrypt_mac_string($mac, $sub, $key, $data, true)),
        bin2hex(tomcrypt_mac_file($mac, $sub, $key, __DIR__ . DIRECTORY_SEPARATOR . 'hello.bin', true))
    );
?>
--EXPECT--
string(40) "4512c7dbb1ebfa0b954fb9cab302bb83a722f59e"
string(40) "4512c7dbb1ebfa0b954fb9cab302bb83a722f59e"
string(40) "4512c7dbb1ebfa0b954fb9cab302bb83a722f59e"
string(40) "4512c7dbb1ebfa0b954fb9cab302bb83a722f59e"

