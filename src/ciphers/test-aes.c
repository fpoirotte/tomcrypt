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
#include <stdio.h>
#include <stdlib.h>

#define BLOCK_SIZE 16

typedef struct {
    char                    subst_path[100];
    FILE                   *substitutions;
} test_aes_data;

static int test_aes_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    test_aes_data          *data;
    unsigned char           hexkey[65];
    unsigned int            i;

    LTC_ARGCHK(key   != NULL);
    LTC_ARGCHK(skey  != NULL);

    if (keylen != 16 && keylen != 24 && keylen != 32) {
       return CRYPT_INVALID_KEYSIZE;
    }

    if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2)) {
       return CRYPT_INVALID_ROUNDS;
    }

    data = (test_aes_data *) malloc(sizeof(test_aes_data));
    if (data == NULL) {
        return CRYPT_ERROR;
    }

    for (i = 0; i < keylen; i++) {
        sprintf(hexkey + (i << 1), "%02x", key[i]);
    }
    sprintf(data->subst_path, "tests/aes_ecb/%s.dat", hexkey);

    data->substitutions = fopen(data->subst_path, "r");
    if (data->substitutions == NULL) {
        free(data);
        return CRYPT_INVALID_ARG;
    }

    skey->data = data;
    return CRYPT_OK;
}

static int test_aes_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    test_aes_data          *data;
    unsigned char           search[BLOCK_SIZE], replace[BLOCK_SIZE];
    short int               i, c;

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);
    LTC_ARGCHK(skey->data != NULL);

    data = (test_aes_data *) skey->data;
    fseek(data->substitutions, 0L, SEEK_SET);
    while (!feof(data->substitutions)) {
        /* Visual Studio does not support the "%hhx" format. */
        for (i = 0; i < BLOCK_SIZE; i++) {
            if (fscanf(data->substitutions, "%02hx", &c) != 1) {
                goto error;
            } else {
                search[i] = (unsigned char) c;
            }
        }

        for (i = 0; i < BLOCK_SIZE; i++) {
            if (fscanf(data->substitutions, "%02hx", &c) != 1) {
                goto error;
            } else {
                replace[i] = (unsigned char) c;
            }
        }

        if (!memcmp(search, pt, BLOCK_SIZE)) {
            memcpy(ct, replace, BLOCK_SIZE);
            return CRYPT_OK;
        }
    }

error:
    return CRYPT_ERROR;
}

static int test_aes_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    test_aes_data          *data;
    unsigned char           search[BLOCK_SIZE], replace[BLOCK_SIZE];
    short int               i, c;

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);
    LTC_ARGCHK(skey->data != NULL);

    data = (test_aes_data *) skey->data;
    fseek(data->substitutions, 0L, SEEK_SET);
    while (!feof(data->substitutions)) {
        /* Visual Studio does not support the "%hhx" format. */
        for (i = 0; i < BLOCK_SIZE; i++) {
            if (fscanf(data->substitutions, "%02hx", &c) != 1) {
                goto error;
            } else {
                search[i] = (unsigned char) c;
            }
        }

        for (i = 0; i < BLOCK_SIZE; i++) {
            if (fscanf(data->substitutions, "%02hx", &c) != 1) {
                goto error;
            } else {
                replace[i] = (unsigned char) c;
            }
        }

        if (!memcmp(replace, ct, BLOCK_SIZE)) {
            memcpy(pt, search, BLOCK_SIZE);
            return CRYPT_OK;
        }
    }

error:
    return CRYPT_ERROR;
}

static void test_aes_done(symmetric_key *skey)
{
    test_aes_data   *data;

    if (skey == NULL || skey->data == NULL) {
        return;
    }

    data = (test_aes_data *) skey->data;
    if (data->substitutions != NULL) {
        fclose(data->substitutions);
        data->substitutions = NULL;
    }

    free(skey->data);
    skey->data = NULL;
}

static int test_aes_keysize(int *keysize)
{
    LTC_ARGCHK(keysize != NULL);

    if (*keysize == 16 || *keysize == 24 || *keysize == 32)
        return CRYPT_OK;
    return CRYPT_INVALID_KEYSIZE;
}

const struct ltc_cipher_descriptor test_aes_desc = {
    "test-aes",
    0x82,
    16, 32,
    16,
    10,
    &test_aes_setup,
    &test_aes_ecb_encrypt,
    &test_aes_ecb_decrypt,
    NULL,
    &test_aes_done,
    &test_aes_keysize,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

