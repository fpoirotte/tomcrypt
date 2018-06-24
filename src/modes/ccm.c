#include <tomcrypt.h>
#include "../compat.h"
#include "crypt_mode.h"

ZEND_EXTERN_MODULE_GLOBALS(tomcrypt)

void php_tomcrypt_xcrypt_ccm(PLTC_CRYPT_PARAM)
{
#ifdef LTC_CCM_MODE
	char           *output, *nonce, *authdata, *in_tag, out_tag[MAXBLOCKSIZE + 1];
	pltc_size       nonce_len, authdata_len, in_tag_len;
	int             err;
	unsigned long   out_tag_len;

	GET_OPT_STRING(options, "nonce", nonce, nonce_len, NULL);
	GET_OPT_STRING(options, "authdata", authdata, authdata_len, NULL);
	GET_OPT_STRING(options, "tag", in_tag, in_tag_len, NULL);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if ((err = ccm_memory(cipher, key, key_len, NULL, nonce, nonce_len, authdata, authdata_len,
		input, input_len, output, out_tag, &out_tag_len, direction)) != CRYPT_OK) {
		efree(output);
		TOMCRYPT_G(last_error) = err;
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		RETURN_FALSE;
	}

    if (direction == PLTC_ENCRYPT) {
	    if (options) {
	        /* Write the tag back into the options. */
		    out_tag[out_tag_len] = '\0';
		    pltc_add_assoc_stringl(options, "tag", out_tag, out_tag_len, 1);
	    }
    } else {
		if (in_tag_len != out_tag_len || memcmp(out_tag, in_tag, out_tag_len)) {
			efree(output);
			TOMCRYPT_G(last_error) = CRYPT_ERROR;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Tag verification failed");
			RETURN_FALSE;
		}
    }

	PLTC_RETURN_STRINGL(output, input_len, 0);
#else
	TOMCRYPT_G(last_error) = CRYPT_INVALID_ARG;
	php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported mode");
	RETURN_FALSE;
#endif
}

