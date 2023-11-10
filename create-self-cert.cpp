
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>
#else
#include <string.h>
#include <stdlib.h>
#include <CSP_WinDef.h>
#include <CSP_WinCrypt.h>
#include "reader/tchar.h"
#endif
#include <WinCryptEx.h>

#include <string>
#include <iostream>
#include <memory>

// #pragma comment(lib, "Crypt32.lib")

bool CreateAndSaveCertificate(const wchar_t* certFilePath)
{
    // Step 1: Acquire a CSP handle for CryptoPro
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT))
    {
        std::cerr << "Error acquiring the CSP handle." << std::endl;
        return false;
    }

    // Step 2: Generate a new key pair
    HCRYPTKEY hKey;
    if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKey))
    {
        std::cerr << "Error generating the key pair." << std::endl;
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Step 3: Create the self-signed certificate
    // PCCERT_CONTEXT pCertContext = NULL;
    // if (!CryptCreateSelfSignCertificate(hCryptProv, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &pCertContext))
    // {
    //     std::cerr << "Error creating the self-signed certificate." << std::endl;
    //     CryptDestroyKey(hKey);
    //     CryptReleaseContext(hCryptProv, 0);
    //     return false;
    // }

    // // Step 4: Save the certificate to a file (in .cer format)
    // if (!CertSaveCertificateContext(pCertContext, CERT_STORE_SAVE_AS_P7_BLOB, CERT_SAVE_TO_FILE, certFilePath, 0, NULL))
    // {
    //     std::cerr << "Error saving the certificate to the file." << std::endl;
    //     CryptDestroyKey(hKey);
    //     CryptReleaseContext(hCryptProv, 0);
    //     CertFreeCertificateContext(pCertContext);
    //     return false;
    // }

    // Clean up resources
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);
    CertFreeCertificateContext(pCertContext);

    return true;
}

int main()
{
    const wchar_t* certFilePath = L"Path_To_Save_Certificate_File.cer";

    if (CreateAndSaveCertificate(certFilePath))
    {
        std::cout << "Certificate created and saved to file successfully." << std::endl;
    }
    else
    {
        std::cerr << "Failed to create and save the certificate." << std::endl;
    }

    return 0;
}
