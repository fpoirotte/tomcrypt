--TEST--
tomcrypt - EAX mode
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_EAX, tomcrypt_list_modes())) {
        print "skip mode not available";
    }
?>
--FILE--
<?php var_dump(in_array(TOMCRYPT_MODE_EAX, tomcrypt_list_modes())); ?>
--EXPECT--
bool(true)
