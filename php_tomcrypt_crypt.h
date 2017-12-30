#ifndef PHP_TOMCRYPT_CRYPT_H
#define PHP_TOMCRYPT_CRYPT_H

#define PLTC_CRYPT_PARAM          INTERNAL_FUNCTION_PARAMETERS, int cipher, char *key, pltc_size key_len, char *input, pltc_size input_len, zval *options, int direction
#define PLTC_CRYPT_PARAM_PASSTHRU INTERNAL_FUNCTION_PARAM_PASSTHRU, cipher, key, key_len, input, input_len, options, direction

#define PLTC_CRYPT_HANDLER(modconst, handler) \
	if (!strncmp(modconst, mode, mode_len)) { \
		handler(PLTC_CRYPT_PARAM_PASSTHRU); \
		return; \
	}

/* Carefully crafted values that match LTC_ENCRYPT/LTC_DECRYPT as defined in LibTomCrypt 1.18+. ;)
   Also matches similar constants from previous versions. */
#define PLTC_ENCRYPT 0
#define PLTC_DECRYPT 1

#endif /* PHP_TOMCRYPT_CRYPT_H */
