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
--ENV--
PLTC_TESTS=1
--FILE--
<?php
    $mode   = TOMCRYPT_MODE_CHACHA20POLY1305;
    $cipher = null;

    # See https://tools.ietf.org/html/rfc7539#page-22
    $opts   = array(
        'iv'        => "\x07\x00\x00\x00@ABCDEFG", // 32-bit fixed-common part + IV
        'authdata'  => pack('H*', str_replace(' ', '', '50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7')),
    );
    $pt     = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    $key    = pack('H*', str_replace(' ', '', '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f'));
    $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, $mode, $opts);
    var_dump(bin2hex($ct));
    var_dump(bin2hex($opts['tag']));

    $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts);
    var_dump($pt === $pt2);

    $tag = $opts['tag'];
    unset($opts['tag']);
    var_dump(tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts));

    $opts['tag'] = $tag;
    unset($opts['authdata']);
    var_dump(tomcrypt_cipher_decrypt($cipher, $key, $ct, $mode, $opts));
?>
--EXPECTF--
string(228) "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
string(32) "1ae10b594f09e26a7e902ecbd0600691"
bool(true)

Warning: tomcrypt_cipher_decrypt(): Invalid tag length (should be between 16 and 128) in %s on line %d
bool(false)

Warning: tomcrypt_cipher_decrypt(): Tag verification failed in %s on line %d
bool(false)

