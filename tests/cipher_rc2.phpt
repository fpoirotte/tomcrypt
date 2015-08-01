--TEST--
tomcrypt - RC2 cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) print "skip extension not loaded";
    if (!defined('TOMCRYPT_CIPHER_RC2')) print "skip cipher not available";
    if (!defined('TOMCRYPT_MODE_ECB')) print "skip mode not available";
?>
--FILE--
<?php
    $cipher = TOMCRYPT_CIPHER_RC2;
    var_dump(
        in_array($cipher, tomcrypt_list_ciphers()),
        tomcrypt_cipher_name($cipher),
        tomcrypt_cipher_block_size($cipher),
        tomcrypt_cipher_min_key_size($cipher),
        tomcrypt_cipher_max_key_size($cipher),
        tomcrypt_cipher_default_rounds($cipher)
    );

    $pt     = 'Hi, hello world!';
    // mcrypt only supports 128 bytes keys.
    $key    = 'This is a secret that should most definitely be kept secret ' .
              'no matter how much you tell me that I shall reveal it to you ' .
              'guys...';
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
    var_dump(bin2hex($ct));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
    var_dump($pt === $pt2);
?>
--EXPECT--
bool(true)
string(3) "rc2"
int(8)
int(8)
int(128)
int(16)
string(32) "120f07b22dc1c279ed986b7ea38ea028"
bool(true)

