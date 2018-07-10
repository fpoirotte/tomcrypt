--TEST--
tomcrypt - ChaCha20-Poly1305 mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
?>
--FILE--
<?php var_dump(in_array(TOMCRYPT_MODE_CHACHA20POLY1305, tomcrypt_list_modes())); ?>
--EXPECT--
bool(true)
