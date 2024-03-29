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
#include <chrono>
#include <iostream>
using namespace std::chrono;

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
    HCRYPTPROV _hProv = 0;
    HCRYPTHASH _hHash = 0;
    HCRYPTKEY _hKey = 0;
    HCRYPTKEY _hPubKey = 0;
    BYTE *_pbHash = NULL;
    BYTE *_pbSignature = NULL;
    BYTE *_pbKeyBlob = NULL;

    const char *CONTAINER = "\\\\.\\HDIMAGE\\cbr2";

public:
    Crypto(/* args */);
    ~Crypto();
    void CleanUp(void);

    void HandleError(const char *s);
    HCRYPTHASH hash(const char *data);
    bool Verify(const char* data, DWORD dwSigLen);
    DWORD Sign(const char* data);
};

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



}

HCRYPTHASH Crypto::hash(const char *data)
{

    BYTE *pbBuffer = (BYTE*)data; 
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
    DWORD dwBlobLen;
    DWORD cbHash;
    //--------------------------------------------------------------------
    // �������� ������� ������� �����������.

    if (CryptCreateHash(
            _hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &_hHash))
    {
        // printf("Hash object created. \n");
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
        // printf("Size of the BLOB determined. \n");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }

    if (!_pbHash)
        _pbHash = new BYTE[cbHash];
    if (!_pbHash)
        HandleError("Out of memory. \n");

    // ����������� ��������� HP_OID � pbHash.
    if (CryptGetHashParam(_hHash,
                          HP_OID,
                          _pbHash,
                          &cbHash,
                          0))
    {
        // printf("Parameters have been written to the pbHash. \n");
    }
    else
    {
        HandleError("Error during CryptGetHashParam.");
    }

    //--------------------------------------------------------------------
    // ���������� ������������������ ���� ������.

    if (CryptHashData(
            _hHash,
            pbBuffer,
            dwBufferLen,
            0))
    {
        // printf("The data buffer has been hashed.\n");
    }
    else
    {
        HandleError("Error during CryptHashData.");
    }

    //--------------------------------------------------------------------
    // ��������� ��������� ������� ������� �����������.
    // CHAR rgbDigits[] = "0123456789abcdef";
    // BYTE rgbHash[GR3411LEN];
    // cbHash = GR3411LEN;
    // if (!CryptGetHashParam(_hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    // {
    //     CryptDestroyHash(_hHash);
    //     CryptReleaseContext(_hProv, 0);
    //     HandleError("CryptGetHashParam failed");
    // }

    // printf("GR3411 hash of file is: ");
    // for(DWORD i = 0; i < cbHash; i++)
    // {
	// printf("%c%c", rgbDigits[rgbHash[i] >> 4],
	//     rgbDigits[rgbHash[i] & 0xf]);
    // }
    // printf("\n");
    return _hHash;

}

DWORD Crypto::Sign(const char* data)
{
    _hHash = this->hash((char*)data);
    // ����������� ������� ������� � ������������� ������.
    DWORD dwSigLen = 0;
    if (CryptSignHash(
            _hHash,
            AT_SIGNATURE,
            NULL,
            0,
            NULL,
            &dwSigLen))
    {
        // printf("Signature length %d found.\n", dwSigLen);
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }
    //--------------------------------------------------------------------
    // ������������� ������ ��� ����� �������.
    if (!_pbSignature)
        _pbSignature = new BYTE[dwSigLen]; ;
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
        // printf("pbSignature is the hash signature.\n");
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }

    // ����������� ������� ������� �����������.
    if (_hHash)
        CryptDestroyHash(_hHash);

    // printf("The hash object has been destroyed.\n");
    // printf("The signing phase of this program is completed.\n\n");

    return dwSigLen;
}

bool Crypto::Verify(const char* data, DWORD dwSigLen)
{

    DWORD dwBlobLen = 0;

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
        // printf("The signature key has been acquired. \n");
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
        // printf("Size of the BLOB for the public key determined. \n");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }
    //--------------------------------------------------------------------
    // ������������� ������ ��� pbKeyBlob.

    // _pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    if (!_pbKeyBlob)
        _pbKeyBlob = new BYTE[dwBlobLen];
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
        // printf("Contents have been written to the BLOB. \n");
    }
    else
    {
        HandleError("Error during CryptExportKey.");
    }

    //--------------------------------------------------------------------
    // �� ������ ����� ��������� ����������� �������.
    // ���� ����� �������� �������������� � ������, ����� ���������
    // ������������ ���������� ���� � �� �� ���������. ���, �������,
    // � ����� PUBLICKEYBLOB ����� ���� ��������� �� �����, e-mail ���������
    // ��� �� ������� ���������.

    // ����� ����������� ������������ ����� pbBuffer, pbSignature,
    // szDescription, pbKeyBlob � �� �����.

    // ���������� ������ pbBuffer ������������ �� ���� ���������
    // ����������� ����� ������.

    // ��������� szDescription �� �����, ����������� ������, �������������.
    // ��� ��� �� ����� ����� ��������, ������� ��� ����� �������
    // ������� CryptSignHash.

    //--------------------------------------------------------------------
    // ��������� �������� ����� ������������, ������� ������ �������� �������,
    // � �������������� ��� � CSP � ������� ������� CryptImportKey. ���
    // ���������� ���������� ��������� ����� � hPubKey.

    BYTE *pbBuffer = (BYTE *)data;
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
    
    // DWORD dwBlobLen;
    // DWORD cbHash;
    // FILE *signature;

    if (CryptImportKey(
            _hProv,
            _pbKeyBlob,
            dwBlobLen,
            0,
            0,
            &_hPubKey))
    {
        // printf("The key has been imported.\n");
    }
    else
    {
        HandleError("Public key import failed.");
    }
    //--------------------------------------------------------------------
    // �������� �������� �������.

    // ���������� ������������������ ���� ������.
    _hHash = this->hash((char*)pbBuffer);

    if (CryptVerifySignature(
            _hHash,
            _pbSignature,
            dwSigLen,
            _hPubKey,
            NULL,
            0))
    {
        // printf("The signature has been verified.\n");
        return true;
    }
    else
    {
        printf("Signature not validated!\n");
        return false;
    }
}

Crypto::~Crypto()
{
    CleanUp();
}


void Crypto::CleanUp(void)
{
    if (_pbSignature)
        // free(_pbSignature);
        delete[] _pbSignature;
    if (_pbHash)
        // free(_pbHash);
        delete[] _pbHash;
    if (_pbKeyBlob)
        // free(_pbKeyBlob);
        delete[] _pbKeyBlob;

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

void Crypto::HandleError(const char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    CleanUp();
    if (!err)
        err = 1;
    exit(err);
}

int main(void)
{
    Crypto sign;
    auto dwSigLen = 0;
    std::string my_new_data_for_sign = "My some data for signing";
    auto count = 100000;
    auto start = system_clock::now();
    for (size_t i = 0; i < count; i++)
    {
        // my_new_data_for_sign += std::to_string(i);
        dwSigLen = sign.Sign(my_new_data_for_sign.c_str());
        if( !sign.Verify(my_new_data_for_sign.c_str(), dwSigLen) )
            throw "Exception bad verify";
    }
    auto end = system_clock::now();
    std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count()/1000.0 << std::endl;

    return 0;
}