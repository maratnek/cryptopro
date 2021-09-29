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
#include <memory>
using namespace std::chrono;

using T_UNIQP_BYTE = std::unique_ptr<BYTE[]>;
using T_PAIR_BYTE = std::pair< T_UNIQP_BYTE, DWORD >;

#include "threads-utils.h"
auto lamda_multi_thread = l_thread_data<std::function<void(size_t, size_t)>>;

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
    T_PAIR_BYTE hash_byte(const char *data);
    bool Verify(const char* data, DWORD dwSigLen);
    DWORD Sign(const char* data);
    void showHash() const;
};

constexpr size_t GR3411LEN = 64;
void Crypto::showHash() const
{
    //--------------------------------------------------------------------
    // Получение параметра объекта функции хэширования.
    static CHAR rgbDigits[] = "0123456789abcdef";
    BYTE rgbHash[GR3411LEN] = {0};
    DWORD cbHash = GR3411LEN;
    if (!CryptGetHashParam(_hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        // CryptDestroyHash(_hHash);
        // CryptReleaseContext(_hProv, 0);
        // HandleError("CryptGetHashParam failed");
        // TODO Error
        return;
    }

    printf("GR3411 hash of file is: ");
    for(DWORD i = 0; i < cbHash; i++)
    {
	printf("%c%c", rgbDigits[rgbHash[i] >> 4],
	    rgbDigits[rgbHash[i] & 0xf]);
    }
    printf("\n");
}

T_PAIR_BYTE Crypto::hash_byte(const char *data)
{
    this->hash(data);
    // BYTE rgbHash[GR3411LEN] = {0};
    T_UNIQP_BYTE rgbHash = std::make_unique<BYTE[]>(GR3411LEN);
    DWORD cbHash = GR3411LEN;
    if (!CryptGetHashParam(_hHash, HP_HASHVAL, rgbHash.get(), &cbHash, 0))
    {
        // CryptDestroyHash(_hHash);
        // CryptReleaseContext(_hProv, 0);
        // HandleError("CryptGetHashParam failed");
        // TODO Error
        return {std::move(rgbHash), cbHash};
    }

    return {std::move(rgbHash), cbHash};
}

Crypto::Crypto(/* args */)
{
    //-------------------------------------------------------------
    // Объявление и инициализация переменных.

    // Получение дескриптора контекста криптографического провайдера.
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

    DWORD cbHash;
    //--------------------------------------------------------------------
    // Создание объекта функции хэширования.

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
    // Передача параметра HP_OID объекта функции хэширования.
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    // Определение размера BLOBа и распределение памяти.

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

    // Копирование параметра HP_OID в pbHash.
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

}

HCRYPTHASH Crypto::hash(const char *data)
{

    BYTE *pbBuffer = (BYTE*)data; 
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
  //--------------------------------------------------------------------
    // Создание объекта функции хэширования.

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
  
    if (!_pbHash)
        HandleError("Out of memory. \n");
    //--------------------------------------------------------------------
    // Вычисление криптографического хэша буфера.

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
    return _hHash;

}

DWORD Crypto::Sign(const char* data)
{
    _hHash = this->hash((char*)data);
    // Определение размера подписи и распределение памяти.
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
    // Распределение памяти под буфер подписи.
    if (!_pbSignature)
        _pbSignature = new BYTE[dwSigLen]; ;
    if (!_pbSignature)
        HandleError("Out of memory.");

    // Подпись объекта функции хэширования.
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

    // Уничтожение объекта функции хэширования.
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
    // Получение открытого ключа подписи. Этот открытый ключ будет
    // использоваться получателем хэша для проверки подписи.
    // В случае, когда получатель имеет доступ к открытому ключю
    // отправителя с помощью сертификата, этот шаг не нужен.

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
    // Экпорт открытого ключа. Здесь открытый ключ экспортируется в
    // PUBLICKEYBOLB для того, чтобы получатель подписанного хэша мог
    // проверить подпись. Этот BLOB может быть записан в файл и передан
    // другому пользователю.

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
    // Распределение памяти под pbKeyBlob.

    // _pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    if (!_pbKeyBlob)
        _pbKeyBlob = new BYTE[dwBlobLen];
    if (!_pbKeyBlob)
        HandleError("Out of memory. \n");

    // Сам экспорт в ключевой BLOB.
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
    // Во второй части программы проверяется подпись.
    // Чаще всего проверка осуществляется в случае, когда различные
    // пользователи используют одну и ту же программу. Хэш, подпись,
    // а также PUBLICKEYBLOB могут быть прочитаны из файла, e-mail сообщения
    // или из другого источника.

    // Здесь используюся определенные ранее pbBuffer, pbSignature,
    // szDescription, pbKeyBlob и их длины.

    // Содержимое буфера pbBuffer представляет из себя некоторые
    // подписанные ранее данные.

    // Указатель szDescription на текст, описывающий данные, подписывается.
    // Это тот же самый текст описания, который был ранее передан
    // функции CryptSignHash.

    //--------------------------------------------------------------------
    // Получение откытого ключа пользователя, который создал цифровую подпись,
    // и импортирование его в CSP с помощью функции CryptImportKey. Она
    // возвращает дескриптор открытого ключа в hPubKey.

    BYTE *pbBuffer = (BYTE *)data;
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
    
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
    // Проверка цифровой подписи.

    // Вычисление криптографического хэша буфера.
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
        delete[] _pbSignature;
    if (_pbHash)
        delete[] _pbHash;
    if (_pbKeyBlob)
        delete[] _pbKeyBlob;

    // Уничтожение объекта функции хэширования.
    if (_hHash)
        CryptDestroyHash(_hHash);

    if (_hKey)
        CryptDestroyKey(_hKey);

    if (_hPubKey)
        CryptDestroyKey(_hPubKey);

    // Освобождение дескриптора провайдера.
    if (_hProv)
        CryptReleaseContext(_hProv, 0);
}

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
    auto count = 100'000;

// only hash

    // CHAR rgbDigits[] = "0123456789abcdef";
    // auto start = system_clock::now();
    // lamda_multi_thread([&rgbDigits](size_t i, size_t max_count)
    //                    {
    //                        Crypto sign;
    //                        std::string some_data = "My some data for signing";
    //                        auto dwSigLen = 0;
    //                        for (; i < max_count; i++)
    //                        {
    //                            auto hash_pair = sign.hash_byte(some_data.c_str());
    //                            auto rgbHash = std::move(hash_pair.first);
    //                         //    printf("GR3411 hash of file is: ");
    //                         //    for (DWORD i = 0; i < hash_pair.second; i++)
    //                         //    {
    //                         //        printf("%c%c", rgbDigits[rgbHash[i] >> 4],
    //                         //               rgbDigits[rgbHash[i] & 0xf]);
    //                         //    }
    //                         //    printf("\n");
    //                        }
    //                    },
    //                    count);
    // auto end = system_clock::now();
    // std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count()/1000.0 << std::endl;

    auto start = system_clock::now();
    lamda_multi_thread([](size_t i, size_t max_count)
                       {
                           Crypto sign;
                           std::string some_data = "My some data for signing";
                           auto dwSigLen = 0;
                           for (; i < max_count; i++)
                           {
                               dwSigLen = sign.Sign(some_data.c_str());
                               if (!sign.Verify(some_data.c_str(), dwSigLen))
                                   throw "Exception bad verify";
                           }
                       },
                       count);
    auto end = system_clock::now();
    std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count()/1000.0 << std::endl;

    return 0;
}