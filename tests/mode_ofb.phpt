--TEST--
tomcrypt - OFB mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    if (!defined('TOMCRYPT_MODE_OFB')) print "skip mode not available";
?>
--FILE--
<?php var_dump(in_array(TOMCRYPT_MODE_OFB, tomcrypt_list_modes())); ?>
--EXPECT--
bool(true)
