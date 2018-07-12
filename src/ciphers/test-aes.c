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

typedef struct {
    unsigned char search[16];
    unsigned char replace[16];
} test_aes_replacement;

typedef struct {
    unsigned char          *key;
    int                     keylen;
    long                    nb_replacements;
    test_aes_replacement   *replacements;
} test_aes_data;

static int test_aes_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    test_aes_data          *data = NULL;
    FILE                   *testdata = NULL;
    char                    testdatapath[100];
    unsigned char           hexkey[65], j;
    unsigned int            i, nb_replacements;
    test_aes_replacement   *replacements = NULL;
    short int               c;

    LTC_ARGCHK(key   != NULL);
    LTC_ARGCHK(skey  != NULL);

    if (keylen != 16 && keylen != 24 && keylen != 32) {
       return CRYPT_INVALID_KEYSIZE;
    }

    if (num_rounds != 0 && num_rounds != (10 + ((keylen/8)-2)*2)) {
       return CRYPT_INVALID_ROUNDS;
    }

    for (i = 0; i < keylen; i++) {
        sprintf(hexkey + (i << 1), "%02x", key[i]);
    }
    sprintf(testdatapath, "tests/aes_ecb/%s.dat", hexkey);

    testdata = fopen(testdatapath, "r");
    if (testdata != NULL) {
        /*
            Determine number of entries; each entry contains 32-byte hex input,
            followed by a space, 32-byte hex output, followed by a line feed.
        */
        fseek(testdata, 0L, SEEK_END);
        nb_replacements = (ftell(testdata) + 1) / (32 + 32 + 2);
        replacements = (test_aes_replacement *) calloc(nb_replacements, sizeof(test_aes_replacement));
        if (replacements == NULL) {
            goto error;
        }
        rewind(testdata);

        for (i = 0; i < nb_replacements; i++) {
            /* We can't use fscanf() here for portability reasons:
               Visual Studio does not support the "%hhx" format. */
            for (j = 0; j < 16; j++) {
                if (fscanf(testdata, "%02hx", &c) != 1) {
                    goto error;
                } else {
                    replacements[i].search[j] = (unsigned char) c;
                }
            }

            for (j = 0; j < 16; j++) {
                if (fscanf(testdata, "%02hx", &c) != 1) {
                    goto error;
                } else {
                    replacements[i].replace[j] = (unsigned char) c;
                }
            }

            printf("replace '");
            for (j = 0; j < 16; j++) {
                printf("%02hhx", replacements[i].search[j]);
            }
            printf("' with '");
            for (j = 0; j < 16; j++) {
                printf("%02hhx", replacements[i].replace[j]);
            }
            printf("'\n");
        }
    }

    data = (test_aes_data *) malloc(sizeof(test_aes_data));
    if (data == NULL) {
        goto error;
    }

    memcpy(data->key, key, keylen);
    data->keylen            = keylen;
    data->nb_replacements   = nb_replacements;
    data->replacements      = replacements;
    skey->data = data;
    return CRYPT_OK;


error:
    if (data != NULL) {
        free(data);
    }

    if (replacements != NULL) {
        free(replacements);
    }
    fclose(testdata);
    return CRYPT_ERROR;
}

static int test_aes_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    test_aes_data  *data;
    long            i;
    unsigned char   key[65], in[33];

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);

    printf("Encrypt: looking for '");
    for (i = 0; i < 16; i++) {
        printf("%02hhx", pt[i]);
    }
    printf("'\n");

    data = (test_aes_data *) skey->data;
    for (i = 0; i < data->nb_replacements; i++) {
        if (memcmp(data->replacements[i].search, pt, 16)) {
            memcpy(ct, data->replacements[i].replace, 16);
            return CRYPT_OK;
        }
    }

    for (i = 0; i < data->keylen; i++) {
        sprintf(key + (i << 1), "%02x", data->key[i]);
    }
    sprintf(in, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        pt[ 0], pt[ 1], pt[ 2], pt[ 3], pt[ 4], pt[ 5], pt[ 6], pt[ 7],
        pt[ 8], pt[ 9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]);
    printf("No match found in ecb_decrypt for key '%s' and input '%s'\n", key, in);

    return CRYPT_ERROR;
}

static int test_aes_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    test_aes_data  *data;
    long            i;
    unsigned char   key[65], in[33];

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);

    printf("Decrypt: looking for '");
    for (i = 0; i < 16; i++) {
        printf("%02hhx", ct[i]);
    }
    printf("'\n");

    data = (test_aes_data *) skey->data;
    for (i = 0; i < data->nb_replacements; i++) {
        if (memcmp(data->replacements[i].replace, ct, 16)) {
            memcpy(pt, data->replacements[i].search, 16);
            return CRYPT_OK;
        }
    }

    for (i = 0; i < data->keylen; i++) {
        sprintf(key + (i << 1), "%02x", data->key[i]);
    }
    sprintf(in, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        ct[ 0], ct[ 1], ct[ 2], ct[ 3], ct[ 4], ct[ 5], ct[ 6], ct[ 7],
        ct[ 8], ct[ 9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15]);
    printf("No match found in ecb_decrypt for key '%s' and input '%s'\n", key, in);

    return CRYPT_ERROR;
}

static void test_aes_done(symmetric_key *skey)
{
    test_aes_data   *data;

    if (skey == NULL) {
        return;
    }

    data = (test_aes_data *) skey->data;
    if (data->replacements != NULL) {
        free(data->replacements);
    }

    free(skey->data);
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

