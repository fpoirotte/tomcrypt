--TEST--
tomcrypt - ECB mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    if (!defined('TOMCRYPT_MODE_ECB')) print "skip mode not available";
?>
--FILE--
<?php var_dump(in_array(TOMCRYPT_MODE_ECB, tomcrypt_list_modes())); ?>
--EXPECT--
bool(true)
