/*
 * File: keyhchain.c.  Original was named cryptoapi.c.
 *
 * Copyright (c) 2004 Peter 'Luna' Runestig <peter@runestig.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This code has been modified from the original version by Brian Raderman 
 * <brian@irregularexpression.org>.  It was changed to work with the Mac OSX
 * Keychain services instead of the Microsoft Crypto API, which was its original
 * intent.
 */

#include "syshead.h"

#if defined(__APPLE__) && defined(USE_CRYPTO) && defined(USE_SSL)

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include "cert_data.h"
#include "common_osx.h"
#include "crypto_osx.h"

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH	36

/* try to funnel any Keychain/CSSM error messages to OpenSSL ERR_... */
#define ERR_LIB_KEYCHAIN (ERR_LIB_USER + 70)
#define KeychainErr(f)   err_put_apple_error((f), __FILE__, __LINE__)
#define KEYCHAIN_F_FIND_IDENTITY	    101
#define KEYCHAIN_F_CREATE_CERT_DATA_FROM_STRING   102
#define KEYCHAIN_F_SIGN_DATA			    103

static ERR_STRING_DATA KEYCHAIN_str_functs[] =	{
    { ERR_PACK(ERR_LIB_KEYCHAIN, 0, 0),				    "Mac OSX Keychain"},
    { ERR_PACK(0, KEYCHAIN_F_FIND_IDENTITY, 0),		    "findIdentity" },
    { ERR_PACK(0, KEYCHAIN_F_CREATE_CERT_DATA_FROM_STRING, 0),	    "createCertDataFromString" },
    { ERR_PACK(0, KEYCHAIN_F_SIGN_DATA, 0),    "signData" },
    { 0, NULL }
};

static void err_put_apple_error(int func, const char *file, int line)
{
    static int init = 0;

    if (!init) {
		ERR_load_strings(ERR_LIB_KEYCHAIN, KEYCHAIN_str_functs);

	    ERR_STRING_DATA *esd = calloc(4, sizeof(ERR_STRING_DATA));
	    if (esd)
		{
			esd[0].error = 101;
			esd[0].string = "Unable to find identity in keychain (certificate + private key)";

			esd[1].error = 102;
			esd[1].string = "Unable to parse certificate description string";

			esd[2].error = 103;
			esd[2].string = "Unable to sign data with private key";

			ERR_load_strings(ERR_LIB_KEYCHAIN, esd);
		}
		
		init++;
    }
	
	ERR_PUT_error(ERR_LIB_KEYCHAIN, func, 0, file, line);
}

/* encrypt */
static int rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    /* I haven't been able to trigger this one, but I want to know if it happens... */
    assert(0);
    return 0;
}

/* verify arbitrary data */
static int rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    /* I haven't been able to trigger this one, but I want to know if it happens... */
    assert(0);
    return 0;
}

/* sign arbitrary data */
static int rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    SecIdentityRef identity = (SecIdentityRef) rsa->meth->app_data;
	int length;
	
    if (!identity) 
	{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
    }
	
    if (padding != RSA_PKCS1_PADDING) 
	{
		RSAerr(RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
		return 0;
    }
	
	CSSM_DATA fromData;
	fromData.Data = (uint8*)from;
	fromData.Length = flen;
	CSSM_DATA sigBuf = signData(identity, fromData);
	length = sigBuf.Length;
	memcpy(to, sigBuf.Data, sigBuf.Length);
	freeSignature(identity, sigBuf);
    return length;
}

/* decrypt */
static int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    /* I haven't been able to trigger this one, but I want to know if it happens... */
    assert(0);
    return 0;
}

/* called at RSA_new */
static int init(RSA *rsa)
{
    return 0;
}

/* called at RSA_free */
static int finish(RSA *rsa)
{
    SecIdentityRef identity = (SecIdentityRef) rsa->meth->app_data;

    if (!identity)
		return 0;
	
	CFRelease(identity);
    free((char *) rsa->meth);
    rsa->meth = NULL;
    return 1;
}

int SSL_CTX_use_Keychain_certificate(SSL_CTX *ssl_ctx, const char *cert_prop)
{
    X509 *cert = NULL;
    RSA *rsa = NULL, *pub_rsa;
    RSA_METHOD *my_rsa_method = calloc(1, sizeof(RSA_METHOD));
	SecIdentityRef identity = NULL;
	
    if (my_rsa_method == NULL) 
	{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
		goto err;
    }

	OSStatus result = 0;
	result = SecKeychainSetUserInteractionAllowed(FALSE);
	printf("SecKeychainSetUserInteractionAllowed returned %d", result);
	result = SecKeychainUnlock(NULL, 0, NULL, FALSE);
	printf("SecKeychainSetUserInteractionAllowed returned %d", result);
	
	CertDataRef pCertDataTemplate = createCertDataFromString(cert_prop);
	identity = findIdentity(pCertDataTemplate);
	destroyCertData(pCertDataTemplate);
	
 	if (!identity) 
	{
	    KeychainErr(KEYCHAIN_F_FIND_IDENTITY);
	    goto err;
	}
	
    CSSM_DATA cssmCertData;
	SecCertificateRef certificate;

    SecIdentityCopyCertificate(identity, &certificate);
	SecCertificateGetData (certificate, &cssmCertData);
	CFRelease(certificate);

    /* cert_context->pbCertEncoded is the cert X509 DER encoded. */
    cert = d2i_X509(NULL, (unsigned char **) &cssmCertData.Data, cssmCertData.Length);
    if (cert == NULL) 
	{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_ASN1_LIB);
		goto err;
    }

    my_rsa_method->name = "Mac OSX Keychain RSA Method";
    my_rsa_method->rsa_pub_enc = rsa_pub_enc;
    my_rsa_method->rsa_pub_dec = rsa_pub_dec;
    my_rsa_method->rsa_priv_enc = rsa_priv_enc;
    my_rsa_method->rsa_priv_dec = rsa_priv_dec;
    /* my_rsa_method->init = init; */
    my_rsa_method->finish = finish;
    my_rsa_method->flags = RSA_METHOD_FLAG_NO_CHECK;
    my_rsa_method->app_data = (char *) identity;

    rsa = RSA_new();
    if (rsa == NULL)
	{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_MALLOC_FAILURE);
		goto err;
    }

    /* cert->cert_info->key->pkey is NULL until we call SSL_CTX_use_certificate(),
     * so we do it here then...  */
    if (!SSL_CTX_use_certificate(ssl_ctx, cert))
		goto err;
	
    /* the public key */
    pub_rsa = cert->cert_info->key->pkey->pkey.rsa;
    /* SSL_CTX_use_certificate() increased the reference count in 'cert', so
     * we decrease it here with X509_free(), or it will never be cleaned up. */
    X509_free(cert);
    cert = NULL;

    /* I'm not sure about what we have to fill in in the RSA, trying out stuff... */
    /* rsa->n indicates the key size */
    rsa->n = BN_dup(pub_rsa->n);
    rsa->flags |= RSA_FLAG_EXT_PKEY;
    if (!RSA_set_method(rsa, my_rsa_method))
		goto err;

    if (!SSL_CTX_use_RSAPrivateKey(ssl_ctx, rsa))
		goto err;
	
    /* SSL_CTX_use_RSAPrivateKey() increased the reference count in 'rsa', so
     * we decrease it here with RSA_free(), or it will never be cleaned up. */
    RSA_free(rsa);
    return 1;

  err:
    if (cert)
		X509_free(cert);
	
    if (rsa)
	{
		RSA_free(rsa);
	}
    else 
	{
		if (my_rsa_method)
			free(my_rsa_method);
		
		if (identity) 
			CFRelease(identity);
    }
    return 0;
}

#else
static void dummy1 (void) {}
#endif				/* __APPLE__ */
