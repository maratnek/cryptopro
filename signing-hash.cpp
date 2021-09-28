/*
* Copyright(C) 2000-2010 Проект ИОК
*
* Этот файл содержит информацию, являющуюся
* собственностью компании Крипто Про.
*
* Любая часть этого файла не может быть скопирована,
* исправлена, переведена на другие языки,
* локализована или модифицирована любым способом,
* откомпилирована, передана по сети с или на
* любую компьютерную систему без предварительного
* заключения соглашения с компанией Крипто Про.
*
* Программный код, содержащийся в этом файле, предназначен
* исключительно для целей обучения и не может быть использован
* для защиты информации.
*
* Компания Крипто-Про не несет никакой
* ответственности за функционирование этого кода.
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

// Начало примера (не следует удалять данный комментарий, он используется
// для автоматической сборки документации)
//--------------------------------------------------------------------
// В этом примере реализованы создание подписи объекта функции хэширования
// и проверка этой электронно-цифровой подписи.
// Замечание: под win32 рекомендуется использовать _s аналоги CRT функций.
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

    void HandleError(char *s);
    HCRYPTHASH hash(const char *data);
    bool Verify(const char* data, DWORD dwSigLen);
    DWORD Sign(const char* data);
};

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



}

HCRYPTHASH Crypto::hash(const char *data)
{

    BYTE *pbBuffer = (BYTE*)data; 
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
    DWORD dwBlobLen;
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
        printf("Hash object created. \n");
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
        printf("Size of the BLOB determined. \n");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }

    _pbHash = (BYTE *)malloc(cbHash);
    if (!_pbHash)
        HandleError("Out of memory. \n");

    // Копирование параметра HP_OID в pbHash.
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

    //--------------------------------------------------------------------
    // Вычисление криптографического хэша буфера.

    if (CryptHashData(
            _hHash,
            pbBuffer,
            dwBufferLen,
            0))
    {
        printf("The data buffer has been hashed.\n");
        for (int i = 0; i < dwBufferLen; i++)
        {
            printf("%0.2d ", pbBuffer[i]);
        }
        printf("\n hash %d\n", _hHash);
        printf("\n");
        
    }
    else
    {
        HandleError("Error during CryptHashData.");
    }

    //--------------------------------------------------------------------
    // Получение параметра объекта функции хэширования.
    CHAR rgbDigits[] = "0123456789abcdef";
    BYTE rgbHash[GR3411LEN];
    cbHash = GR3411LEN;
    if (!CryptGetHashParam(_hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        CryptDestroyHash(_hHash);
        CryptReleaseContext(_hProv, 0);
        HandleError("CryptGetHashParam failed");
    }

    printf("GR3411 hash of file is: ");
    for(DWORD i = 0; i < cbHash; i++)
    {
	printf("%c%c", rgbDigits[rgbHash[i] >> 4],
	    rgbDigits[rgbHash[i] & 0xf]);
    }
    printf("\n");
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
        printf("Signature length %d found.\n", dwSigLen);
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }
    //--------------------------------------------------------------------
    // Распределение памяти под буфер подписи.

    // _pbSignature = (BYTE *)malloc(dwSigLen);
    _pbSignature = new BYTE[dwSigLen]; //(BYTE *)malloc(dwSigLen);
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
        printf("pbSignature is the hash signature.\n");
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }

    FILE *signature;
    //if(!fopen_s(&signature, "signature.txt", "w+b" ))
    if (!(signature = fopen("signature.txt", "w+b")))
        HandleError("Problem opening the file signature.txt\n");

    fwrite(_pbSignature, 1, dwSigLen, signature);
    fclose(signature);

    // Уничтожение объекта функции хэширования.
    if (_hHash)
        CryptDestroyHash(_hHash);

    printf("The hash object has been destroyed.\n");
    printf("The signing phase of this program is completed.\n\n");

    return dwSigLen;
}

bool Crypto::Verify(const char* data, DWORD dwSigLen)
{

    DWORD dwBlobLen;

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
        printf("The signature key has been acquired. \n");
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
        printf("Size of the BLOB for the public key determined. \n");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }
    //--------------------------------------------------------------------
    // Распределение памяти под pbKeyBlob.

    _pbKeyBlob = (BYTE *)malloc(dwBlobLen);
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
        printf("Contents have been written to the BLOB. \n");
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

    
    // DWORD dwBlobLen;
    DWORD cbHash;
    FILE *signature;

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
    //--------------------------------------------------------------------
    // Создание нового объекта функции хэширования.

    // if (CryptCreateHash(
    //         _hProv,
    //         CALG_GR3411_2012_256,
    //         0,
    //         0,
    //         &_hHash))
    // {
    //     printf("The hash object has been recreated. \n");
    // }
    // else
    // {
    //     HandleError("Error during CryptCreateHash.");
    // }

    // //--------------------------------------------------------------------

    // if (CryptHashData(
    //         _hHash,
    //         pbBuffer,
    //         dwBufferLen,
    //         0))
    // {
    //     printf("The new hash been created.\n");
    // }
    // else
    // {
    //     HandleError("Error during CryptHashData.");
    // }
    //--------------------------------------------------------------------
    // Проверка цифровой подписи.

    // Вычисление криптографического хэша буфера.
    _hHash = this->hash(data);

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
}

Crypto::~Crypto()
{
    CleanUp();
}

#include <iostream>
int main(void)
{
    Crypto sign;

    const char* data = "The data that is to be hashed and signed.";
    auto dwSigLen = sign.Sign(data);
    sign.Verify(data, dwSigLen);

    std::cout << "Start loop " << std::endl;
    auto count = 100;
    for (size_t i = 0; i < count; i++)
    {
        std::string my_new_data_for_sign = "My some data for signing";
        dwSigLen = sign.Sign(my_new_data_for_sign.c_str());
        sign.Verify(my_new_data_for_sign.c_str(), dwSigLen);
    }

    return 0;
}

void Crypto::CleanUp(void)
{
    if (_pbSignature)
        // free(_pbSignature);
        delete[] _pbSignature;
    if (_pbHash)
        free(_pbHash);
    if (_pbKeyBlob)
        free(_pbKeyBlob);

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

// Конец примера
// (не следует удалять данный комментарий, он используется
//  для автоматической сборки документации)

//--------------------------------------------------------------------
//  В этом примере используется функция HandleError, функция обработки
//  простых ошибок, для печати сообщения и выхода из программы.
//  В большинстве приложений эта функция заменяется другой функцией,
//  которая выводит более полное сообщение об ошибке.

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
