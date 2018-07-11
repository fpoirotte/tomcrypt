--TEST--
tomcrypt - NULL cipher
--SKIPIF--
<?php
    if (!extension_loaded("tomcrypt")) {
        print "skip extension not loaded";
    } elseif (!in_array(TOMCRYPT_MODE_ECB, tomcrypt_list_modes())) {
        print "skip ECB mode not available";
    }
?>
--ENV--
return <<<EOF
PLTC_NULL=1
EOF;
--FILE--
<?php
    foreach (array(TOMCRYPT_CIPHER_NULL_REGULAR, TOMCRYPT_CIPHER_NULL_FAST, TOMCRYPT_CIPHER_NULL_128) as $cipher) {
        var_dump(
            tomcrypt_cipher_block_size($cipher),
            tomcrypt_cipher_min_key_size($cipher),
            tomcrypt_cipher_max_key_size($cipher),
            tomcrypt_cipher_default_rounds($cipher)
        );

        // The regular null cipher does not encrypt anything
        // and does not require blocksize alignment.
        // The 128-bit null cipher requires 128-bit blocks of data,
        // while the fast null cipher requires word-aligned blocks of data,
        // that is usually 32-bit blocks or 64-bit blocks.
        //
        // The following plain text is 128-bit long, meaning it
        // should accomodate well with each null cipher.
        $pt     = "Some plain text.";
        $key    = "";
        $ct     = tomcrypt_cipher_encrypt($cipher, $key, $pt, TOMCRYPT_MODE_ECB);
        var_dump($ct);

        $pt2    = tomcrypt_cipher_decrypt($cipher, $key, $ct, TOMCRYPT_MODE_ECB);
        var_dump($pt === $pt2);
    }
?>
--EXPECTF--
int(1)
int(0)
int(0)
int(1)
string(16) "Some plain text."
bool(true)
int(%d)
int(0)
int(0)
int(1)
string(16) "Some plain text."
bool(true)
int(16)
int(0)
int(0)
int(1)
string(16) "Some plain text."
bool(true)

