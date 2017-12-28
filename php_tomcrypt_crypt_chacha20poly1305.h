#include <tomcrypt.h>
#include "php_tomcrypt_compat.h"
#include "php_tomcrypt_crypt.h"

static void php_tomcrypt_xcrypt_chacha20poly1305(PLTC_CRYPT_PARAM)
{
#ifdef LTC_CHACHA20POLY1305_MODE
	char          *output, *iv, *authdata, *in_tag, out_tag[MAXBLOCKSIZE + 1];
	int            iv_len, authdata_len, in_tag_len, err;
	unsigned long  out_tag_len;

	GET_OPT_STRING(options, "iv", iv, iv_len, NULL);
	GET_OPT_STRING(options, "authdata", authdata, authdata_len, NULL);
	GET_OPT_STRING(options, "tag", in_tag, in_tag_len, NULL);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

	if ((err = chacha20poly1305_memory(key, key_len, iv, iv_len, authdata, authdata_len,
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
#endif
}

