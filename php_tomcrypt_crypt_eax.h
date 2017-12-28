#include <tomcrypt.h>
#include "php_tomcrypt_compat.h"
#include "php_tomcrypt_crypt.h"

static void php_tomcrypt_xcrypt_eax(PLTC_CRYPT_PARAM)
{
#ifdef LTC_EAX_MODE
	char          *output, *nonce, *authdata, *in_tag, out_tag[MAXBLOCKSIZE + 1];
	int            nonce_len, authdata_len, in_tag_len, err, res;
	unsigned long  out_tag_len;

	GET_OPT_STRING(options, "nonce", nonce, nonce_len, NULL);
	GET_OPT_STRING(options, "authdata", authdata, authdata_len, NULL);
	GET_OPT_STRING(options, "tag", in_tag, in_tag_len, NULL);

	output = emalloc(input_len + 1);
	output[input_len] = '\0';

    if (direction == PLTC_ENCRYPT) {
	    if ((err = eax_encrypt_authenticate_memory(
		    cipher, key, key_len, nonce, nonce_len, authdata, authdata_len,
		    input, input_len, output, out_tag, &out_tag_len)) != CRYPT_OK) {
		    efree(output);
			TOMCRYPT_G(last_error) = err;
		    php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
		    RETURN_FALSE;
	    }

	    /* Write the tag back. */
	    if (options) {
		    out_tag[out_tag_len] = '\0';
		    pltc_add_assoc_stringl(options, "tag", out_tag, out_tag_len, 1);
	    }
    } else {
		if ((err = eax_decrypt_verify_memory(
			cipher, key, key_len, nonce, nonce_len, authdata, authdata_len,
			input, input_len, output, in_tag, (unsigned long) in_tag_len, &res)) != CRYPT_OK) {
			efree(output);
			TOMCRYPT_G(last_error) = err;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s", error_to_string(err));
			RETURN_FALSE;
		}

	    /* Tag verification failed. */
		if (res != 1) {
			efree(output);
			TOMCRYPT_G(last_error) = CRYPT_ERROR;
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Tag verification failed");
			RETURN_FALSE;
		}
    }

	PLTC_RETURN_STRINGL(output, input_len, 0);
#endif
}

