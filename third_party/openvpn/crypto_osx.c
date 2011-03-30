/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010 Brian Raderman <brian@irregularexpression.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "crypto_osx.h"
#include <CommonCrypto/CommonDigest.h>

CSSM_DATA signData(SecIdentityRef identity, CSSM_DATA dataBuf)
{
    SecKeyRef privateKey;
    
    SecIdentityCopyPrivateKey(identity,  &privateKey); 
    const CSSM_ACCESS_CREDENTIALS *pCredentials;
    SecKeyGetCredentials(privateKey, CSSM_ACL_AUTHORIZATION_SIGN, kSecCredentialTypeDefault, &pCredentials); 
    
    CSSM_CSP_HANDLE cspHandle;
    SecKeyGetCSPHandle(privateKey, &cspHandle);
    
    const CSSM_KEY *pCssmKey;
    SecKeyGetCSSMKey (privateKey, &pCssmKey); 
    
    CSSM_DATA signBuf;
    signBuf.Data = NULL;
    signBuf.Length = 0;
    
    if (!(pCssmKey->KeyHeader.KeyUsage & CSSM_KEYUSE_SIGN))
	{
		CFRelease(privateKey);
		return signBuf;
	}
    
    CSSM_CC_HANDLE cryptoContextHandle;
    CSSM_CSP_CreateSignatureContext(cspHandle, CSSM_ALGID_RSA, pCredentials, pCssmKey, &cryptoContextHandle);
	
    CSSM_SignData(cryptoContextHandle, &dataBuf, 1, CSSM_ALGID_NONE, &signBuf);
    
    CSSM_DeleteContext(cryptoContextHandle);
    CFRelease(privateKey);
    return signBuf;
}

void freeSignature(SecIdentityRef identity, CSSM_DATA sigBuf)
{
    SecKeyRef privateKey;
    
    SecIdentityCopyPrivateKey(identity,  &privateKey); 
    
    CSSM_CSP_HANDLE cspHandle;
    SecKeyGetCSPHandle(privateKey, &cspHandle);
	
	CSSM_API_MEMORY_FUNCS memFuncs;
	CSSM_GetAPIMemoryFunctions(cspHandle, &memFuncs);	
	
	memFuncs.free_func(sigBuf.Data, memFuncs.AllocRef);
}

