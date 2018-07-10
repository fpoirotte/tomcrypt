--TEST--
tomcrypt - OCB mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
?>
--FILE--
<?php var_dump(in_array(TOMCRYPT_MODE_OCB, tomcrypt_list_modes())); ?>
--EXPECT--
bool(true)
