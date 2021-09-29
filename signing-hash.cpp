/*
* Copyright(C) 2000-2010 ������ ���
*
* ���� ���� �������� ����������, ����������
* �������������� �������� ������ ���.
*
* ����� ����� ����� ����� �� ����� ���� �����������,
* ����������, ���������� �� ������ �����,
* ������������ ��� �������������� ����� ��������,
* ���������������, �������� �� ���� � ��� ��
* ����� ������������ ������� ��� ����������������
* ���������� ���������� � ��������� ������ ���.
*
* ����������� ���, ������������ � ���� �����, ������������
* ������������� ��� ����� �������� � �� ����� ���� �����������
* ��� ������ ����������.
*
* �������� ������-��� �� ����� �������
* ��������������� �� ���������������� ����� ����.
*/

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

// my
#include <string>

// ������ ������� (�� ������� ������� ������ �����������, �� ������������
// ��� �������������� ������ ������������)
//--------------------------------------------------------------------
// � ���� ������� ����������� �������� ������� ������� ������� �����������
// � �������� ���� ����������-�������� �������.
// ���������: ��� win32 ������������� ������������ _s ������� CRT �������.
//--------------------------------------------------------------------
#define GR3411LEN  64
class Crypto
{
private:
    /* data */
    static HCRYPTPROV _hProv;
    static HCRYPTHASH _hHash;
    static HCRYPTKEY _hKey;
    static HCRYPTKEY _hPubKey;
    static BYTE *_pbHash;
    static BYTE *_pbSignature;
    static BYTE *_pbKeyBlob;
    DWORD cbHash;

    const char *CONTAINER = "\\\\.\\HDIMAGE\\cbr2";

public:
    Crypto(/* args */);
    ~Crypto();
    void CleanUp(void);

    void HandleError(char *s);
    HCRYPTHASH hash(BYTE *data, DWORD len);
    // bool Verify(const char* data, DWORD dwSigLen);
    DWORD Sign(BYTE *pbBuffer, DWORD dwBufferLen);
};

HCRYPTPROV Crypto::_hProv = 0;
HCRYPTHASH Crypto::_hHash = 0;
HCRYPTKEY Crypto::_hKey = 0;
HCRYPTKEY Crypto::_hPubKey = 0;
BYTE* Crypto::_pbHash = NULL;
BYTE* Crypto::_pbSignature = NULL;
BYTE* Crypto::_pbKeyBlob = NULL;


Crypto::Crypto(/* args */)
{
   //-------------------------------------------------------------
    // ���������� � ������������� ����������.

    // ��������� ����������� ��������� ������������������ ����������.
    if (CryptAcquireContext(
            &_hProv,
            CONTAINER,
            NULL,
            PROV_GOST_2012_256,
            0))
    {
        printf("CSP context acquired.\n");
    }
    else
    {
        HandleError("Error during CryptAcquireContext.");
    }

    BYTE *pbBuffer = (BYTE *)"The data that is to be hashed and signed.";
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
    this->Sign(pbBuffer, dwBufferLen);
}

HCRYPTHASH Crypto::hash(BYTE *pbBuffer, DWORD dwBufferLen)
{
 //--------------------------------------------------------------------
    // �������� ������� ������� �����������.

    if (CryptCreateHash(
            _hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &_hHash))
    {
        printf("Hash object created. \n");
    }
    else
    {
        HandleError("Error during CryptCreateHash.");
    }

    //--------------------------------------------------------------------
    // ���������� ������������������ ���� ������.

    if (CryptHashData(
            _hHash,
            pbBuffer,
            dwBufferLen,
            0))
    {
        printf("The data buffer has been hashed.\nHash is : %lld\n", _hHash);
    }
    else
    {
        HandleError("Error during CryptHashData.");
    }
    return _hHash;
 }

 DWORD Crypto::Sign(BYTE *pbBuffer, DWORD dwBufferLen)
 {
    
    DWORD dwSigLen;
    DWORD dwBlobLen;

    // INIT for hash
    if (CryptCreateHash(
            _hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &_hHash))
    {
        printf("Hash object created. \n");
    }
    else
    {
        HandleError("Error during CryptCreateHash.");
    }

    //--------------------------------------------------------------------
    // �������� ��������� HP_OID ������� ������� �����������.
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    // ����������� ������� BLOB� � ������������� ������.

    if (CryptGetHashParam(_hHash,
                          HP_OID,
                          NULL,
                          &cbHash,
                          0))
    {
        printf("Size of the BLOB determined. \n");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }

    if (!_pbHash)
        _pbHash = (BYTE *)malloc(cbHash);
    if (!_pbHash)
        HandleError("Out of memory. \n");

    // ����������� ��������� HP_OID � pbHash.
    if (CryptGetHashParam(_hHash,
                          HP_OID,
                          _pbHash,
                          &cbHash,
                          0))
    {
        printf("Parameters have been written to the pbHash. \n");
    }
    else
    {
        HandleError("Error during CryptGetHashParam.");
    }

    _hHash = this->hash(pbBuffer, dwBufferLen);

    // ����������� ������� ������� � ������������� ������.
    dwSigLen = 0;
    if (CryptSignHash(
            _hHash,
            AT_SIGNATURE,
            NULL,
            0,
            NULL,
            &dwSigLen))
    {
        printf("Signature length %d found.\n", dwSigLen);
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }
    //--------------------------------------------------------------------
    // ������������� ������ ��� ����� �������.

    _pbSignature = (BYTE *)malloc(dwSigLen);
    if (!_pbSignature)
        HandleError("Out of memory.");

    // ������� ������� ������� �����������.
    if (CryptSignHash(
            _hHash,
            AT_SIGNATURE,
            NULL,
            0,
            _pbSignature,
            &dwSigLen))
    {
        printf("pbSignature is the hash signature.\n");
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }

    // ����������� ������� ������� �����������.
    if (_hHash)
        CryptDestroyHash(_hHash);

    printf("The hash object has been destroyed.\n");
    printf("The signing phase of this program is completed.\n\n");

    //--------------------------------------------------------------------
    // �� ������ ����� ��������� ����������� �������.
  //--------------------------------------------------------------------
    // ��������� ��������� ����� �������. ���� �������� ���� �����
    // �������������� ����������� ���� ��� �������� �������.
    // � ������, ����� ���������� ����� ������ � ��������� �����
    // ����������� � ������� �����������, ���� ��� �� �����.

    if (CryptGetUserKey(
            _hProv,
            AT_SIGNATURE,
            &_hKey))
    {
        printf("The signature key has been acquired. \n");
    }
    else
    {
        HandleError("Error during CryptGetUserKey for signkey.");
    }
    //--------------------------------------------------------------------
    // ������ ��������� �����. ����� �������� ���� �������������� �
    // PUBLICKEYBOLB ��� ����, ����� ���������� ������������ ���� ���
    // ��������� �������. ���� BLOB ����� ���� ������� � ���� � �������
    // ������� ������������.

    if (CryptExportKey(
            _hKey,
            0,
            PUBLICKEYBLOB,
            0,
            NULL,
            &dwBlobLen))
    {
        printf("Size of the BLOB for the public key determined. \n");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }
    //--------------------------------------------------------------------
    // ������������� ������ ��� pbKeyBlob.

    _pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    if (!_pbKeyBlob)
        HandleError("Out of memory. \n");

    // ��� ������� � �������� BLOB.
    if (CryptExportKey(
            _hKey,
            0,
            PUBLICKEYBLOB,
            0,
            _pbKeyBlob,
            &dwBlobLen))
    {
        printf("Contents have been written to the BLOB. \n");
    }
    else
    {
        HandleError("Error during CryptExportKey.");
    }
    if (CryptImportKey(
            _hProv,
            _pbKeyBlob,
            dwBlobLen,
            0,
            0,
            &_hPubKey))
    {
        printf("The key has been imported.\n");
    }
    else
    {
        HandleError("Public key import failed.");
    }

    _hHash = this->hash(pbBuffer, dwBufferLen);

    //--------------------------------------------------------------------
    // �������� �������� �������.

    if (CryptVerifySignature(
            _hHash,
            _pbSignature,
            dwSigLen,
            _hPubKey,
            NULL,
            0))
    {
        printf("The signature has been verified.\n");
    }
    else
    {
        printf("Signature not validated!\n");
    }
    return 0;
 }

// HCRYPTHASH Crypto::hash(const char *data)
// {

//     BYTE *pbBuffer = (BYTE*)data; 
//     DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
//     DWORD dwBlobLen;
//     DWORD cbHash;
//     //--------------------------------------------------------------------
//     // �������� ������� ������� �����������.

//     if (CryptCreateHash(
//             _hProv,
//             CALG_GR3411_2012_256,
//             0,
//             0,
//             &_hHash))
//     {
//         printf("Hash object created. \n");
//     }
//     else
//     {
//         HandleError("Error during CryptCreateHash.");
//     }

//     //--------------------------------------------------------------------
//     // �������� ��������� HP_OID ������� ������� �����������.
//     //--------------------------------------------------------------------

//     //--------------------------------------------------------------------
//     // ����������� ������� BLOB� � ������������� ������.

//     if (CryptGetHashParam(_hHash,
//                           HP_OID,
//                           NULL,
//                           &cbHash,
//                           0))
//     {
//         printf("Size of the BLOB determined. \n");
//     }
//     else
//     {
//         HandleError("Error computing BLOB length.");
//     }

//     _pbHash = (BYTE *)malloc(cbHash);
//     if (!_pbHash)
//         HandleError("Out of memory. \n");

//     // ����������� ��������� HP_OID � pbHash.
//     if (CryptGetHashParam(_hHash,
//                           HP_OID,
//                           _pbHash,
//                           &cbHash,
//                           0))
//     {
//         printf("Parameters have been written to the pbHash. \n");
//     }
//     else
//     {
//         HandleError("Error during CryptGetHashParam.");
//     }

//     //--------------------------------------------------------------------
//     // ���������� ������������������ ���� ������.

//     if (CryptHashData(
//             _hHash,
//             pbBuffer,
//             dwBufferLen,
//             0))
//     {
//         printf("The data buffer has been hashed.\n");
//         // for (int i = 0; i < dwBufferLen; i++)
//         // {
//         //     printf("%0.2d ", pbBuffer[i]);
//         // }
//         // printf("\n hash %d\n", _hHash);
//         // printf("\n");
        
//     }
//     else
//     {
//         HandleError("Error during CryptHashData.");
//     }

//     //--------------------------------------------------------------------
//     // ��������� ��������� ������� ������� �����������.
//     // CHAR rgbDigits[] = "0123456789abcdef";
//     // BYTE rgbHash[GR3411LEN];
//     // cbHash = GR3411LEN;
//     // if (!CryptGetHashParam(_hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
//     // {
//     //     CryptDestroyHash(_hHash);
//     //     CryptReleaseContext(_hProv, 0);
//     //     HandleError("CryptGetHashParam failed");
//     // }

//     // printf("GR3411 hash of file is: ");
//     // for(DWORD i = 0; i < cbHash; i++)
//     // {
// 	// printf("%c%c", rgbDigits[rgbHash[i] >> 4],
// 	//     rgbDigits[rgbHash[i] & 0xf]);
//     // }
//     // printf("\n");
//     return _hHash;

// }

// DWORD Crypto::Sign(const char* data)
// {
//     _hHash = this->hash((char*)data);
//     // ����������� ������� ������� � ������������� ������.
//     DWORD dwSigLen = 0;
//     if (CryptSignHash(
//             _hHash,
//             AT_SIGNATURE,
//             NULL,
//             0,
//             NULL,
//             &dwSigLen))
//     {
//         printf("Signature length %d found.\n", dwSigLen);
//     }
//     else
//     {
//         HandleError("Error during CryptSignHash.");
//     }
//     //--------------------------------------------------------------------
//     // ������������� ������ ��� ����� �������.

//     _pbSignature = (BYTE *)malloc(dwSigLen);
//     // _pbSignature = new BYTE[dwSigLen]; //(BYTE *)malloc(dwSigLen);
//     if (!_pbSignature)
//         HandleError("Out of memory.");

//     // ������� ������� ������� �����������.
//     if (CryptSignHash(
//             _hHash,
//             AT_SIGNATURE,
//             NULL,
//             0,
//             _pbSignature,
//             &dwSigLen))
//     {
//         printf("pbSignature is the hash signature.\n");
//     }
//     else
//     {
//         HandleError("Error during CryptSignHash.");
//     }

//     // FILE *signature;
//     // if (!(signature = fopen("signature.txt", "w+b")))
//     //     HandleError("Problem opening the file signature.txt\n");

//     // fwrite(_pbSignature, 1, dwSigLen, signature);
//     // fclose(signature);

//     // ����������� ������� ������� �����������.
//     if (_hHash)
//         CryptDestroyHash(_hHash);

//     printf("The hash object has been destroyed.\n");
//     printf("The signing phase of this program is completed.\n\n");

//     return dwSigLen;
// }

// bool Crypto::Verify(const char* data, DWORD dwSigLen)
// {

//     DWORD dwBlobLen;

//     //--------------------------------------------------------------------
//     // ��������� ��������� ����� �������. ���� �������� ���� �����
//     // �������������� ����������� ���� ��� �������� �������.
//     // � ������, ����� ���������� ����� ������ � ��������� �����
//     // ����������� � ������� �����������, ���� ��� �� �����.

//     if (CryptGetUserKey(
//             _hProv,
//             AT_SIGNATURE,
//             &_hKey))
//     {
//         printf("The signature key has been acquired. \n");
//     }
//     else
//     {
//         HandleError("Error during CryptGetUserKey for signkey.");
//     }
//     //--------------------------------------------------------------------
//     // ������ ��������� �����. ����� �������� ���� �������������� �
//     // PUBLICKEYBOLB ��� ����, ����� ���������� ������������ ���� ���
//     // ��������� �������. ���� BLOB ����� ���� ������� � ���� � �������
//     // ������� ������������.

//     if (CryptExportKey(
//             _hKey,
//             0,
//             PUBLICKEYBLOB,
//             0,
//             NULL,
//             &dwBlobLen))
//     {
//         printf("Size of the BLOB for the public key determined. \n");
//     }
//     else
//     {
//         HandleError("Error computing BLOB length.");
//     }
//     //--------------------------------------------------------------------
//     // ������������� ������ ��� pbKeyBlob.

//     _pbKeyBlob = (BYTE *)malloc(dwBlobLen);
//     if (!_pbKeyBlob)
//         HandleError("Out of memory. \n");

//     // ��� ������� � �������� BLOB.
//     if (CryptExportKey(
//             _hKey,
//             0,
//             PUBLICKEYBLOB,
//             0,
//             _pbKeyBlob,
//             &dwBlobLen))
//     {
//         printf("Contents have been written to the BLOB. \n");
//     }
//     else
//     {
//         HandleError("Error during CryptExportKey.");
//     }

//     if (CryptImportKey(
//             _hProv,
//             _pbKeyBlob,
//             dwBlobLen,
//             0,
//             0,
//             &_hPubKey))
//     {
//         printf("The key has been imported.\n");
//     }
//     else
//     {
//         HandleError("Public key import failed.");
//     }
   
//     _hHash = this->hash(data);

//     if (CryptVerifySignature(
//             _hHash,
//             _pbSignature,
//             dwSigLen,
//             _hPubKey,
//             NULL,
//             0))
//     {
//         printf("The signature has been verified.\n");
//     }
//     else
//     {
//         printf("Signature not validated!\n");
//     }
// }

Crypto::~Crypto()
{
    CleanUp();
}

#include <iostream>
int main(void)
{
    Crypto sign;

    const char* data = "The data that is to be hashed and signed.";
    // auto dwSigLen = sign.Sign(data);
    // sign.Verify(data, dwSigLen);

    std::cout << "Start loop " << std::endl;
    auto count = 100;
    for (size_t i = 0; i < count; i++)
    {
       Crypto sign2; 
        // std::string my_new_data_for_sign = "My some data for signing";
        // dwSigLen = sign.Sign(my_new_data_for_sign.c_str());
        // sign.Verify(my_new_data_for_sign.c_str(), dwSigLen);
    }

    return 0;
}

void Crypto::CleanUp(void)
{
    if (_pbSignature)
    {
        free(_pbSignature);
        _pbSignature = NULL;
    }
    if (_pbHash)
    {
        free(_pbHash);
        _pbHash = NULL;
    }
    if (_pbKeyBlob)
    {
        free(_pbKeyBlob);
        _pbKeyBlob = NULL;
    }

    // ����������� ������� ������� �����������.
    if (_hHash)
        CryptDestroyHash(_hHash);

    if (_hKey)
        CryptDestroyKey(_hKey);

    if (_hPubKey)
        CryptDestroyKey(_hPubKey);

    // ������������ ����������� ����������.
    if (_hProv)
        CryptReleaseContext(_hProv, 0);
}

// ����� �������
// (�� ������� ������� ������ �����������, �� ������������
//  ��� �������������� ������ ������������)

//--------------------------------------------------------------------
//  � ���� ������� ������������ ������� HandleError, ������� ���������
//  ������� ������, ��� ������ ��������� � ������ �� ���������.
//  � ����������� ���������� ��� ������� ���������� ������ ��������,
//  ������� ������� ����� ������ ��������� �� ������.

void Crypto::HandleError(char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    CleanUp();
    if (!err)
        err = 1;
    exit(err);
}
