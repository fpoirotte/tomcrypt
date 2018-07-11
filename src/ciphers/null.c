/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2018 The PHP Group                                     |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: François Poirotte <clicky@erebot.net>                        |
  +----------------------------------------------------------------------+
*/

#include <tomcrypt.h>

int null_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    LTC_ARGCHK(key   != NULL);
    LTC_ARGCHK(skey  != NULL);

    if (keylen != 0) {
       return CRYPT_INVALID_KEYSIZE;
    }

    if (num_rounds != 0 && num_rounds != 1) {
       return CRYPT_INVALID_ROUNDS;
    }

    return CRYPT_OK;
}

int null_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);

    *ct = *pt;
    return CRYPT_OK;
}

#ifdef LTC_FAST
int null_ecb_encrypt_fast(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);

    *(LTC_FAST_TYPE_PTR_CAST(ct)) = *(LTC_FAST_TYPE_PTR_CAST(pt));
    return CRYPT_OK;
}
#endif

int null_ecb_encrypt_128(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    int i;

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);

    for (i = 0; i < 16; i++) {
        *(ct + i) = *(pt + i);
    }
    return CRYPT_OK;
}

int null_test(void)
{
   return CRYPT_NOP;
}

void null_done(symmetric_key *skey)
{
}

int null_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);
   if (*keysize >= 0) {
      *keysize = 0;
      return CRYPT_OK;
   } else {
      return CRYPT_INVALID_KEYSIZE;
   }
}

const struct ltc_cipher_descriptor null_128_desc =
{
    /* "null" cipher, with a fixed 128-bit block size */
    "null-128",
    0x80, /* ID: this particular ID probably won't be used by LibTomCrypt itself
             for a long time (currently, the biggest ID used is < 0x20). */
    0, 0, /* minimum/maximum key size (in bytes) */
    16,   /* block size (in bytes) */
    1,    /* default number of rounds */
    &null_setup,
    &null_ecb_encrypt_128,
    &null_ecb_encrypt_128, /* Decryption is the same as encrypton */
    &null_test,
    &null_done,
    &null_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
}, null_fast_desc = {
    /* fast "null" cipher, with a word-aligned block size for performance */
    "null-fast",
    0x81,
    0, 0,
#ifdef LTC_FAST
    sizeof(LTC_FAST_TYPE),
#else
    1,
#endif
    1,
    &null_setup,
#ifdef LTC_FAST
    &null_ecb_encrypt_fast,
    &null_ecb_encrypt_fast,
#else
    &null_ecb_encrypt,
    &null_ecb_encrypt,
#endif
    &null_test,
    &null_done,
    &null_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
}, null_desc = {
    /* regular "null" cipher, with a fixed 8-bit block size */
    "null",
    0x82,
    0, 0,
    1,
    1,
    &null_setup,
    &null_ecb_encrypt,
    &null_ecb_encrypt,
    &null_test,
    &null_done,
    &null_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

