--TEST--
tomcrypt - ChaCha20-Poly1305 mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_CHACHA20POLY1305, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--FILE--
<?php
    var_dump();
?>
--EXPECT--
bool(true)
