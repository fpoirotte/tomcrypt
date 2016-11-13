--TEST--
tomcrypt - LRW mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    if (!defined('TOMCRYPT_MODE_LRW')) print "skip mode not available";
?>
--FILE--
<?php var_dump(in_array(TOMCRYPT_MODE_LRW, tomcrypt_list_modes())); ?>
--EXPECT--
bool(true)
