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

// Начало примера (не следует удалять данный комментарий, он используется
// для автоматической сборки документации)
//--------------------------------------------------------------------
// В этом примере реализованы создание подписи объекта функции хэширования
// и проверка этой электронно-цифровой подписи.
// Замечание: под win32 рекомендуется использовать _s аналоги CRT функций.
//--------------------------------------------------------------------

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#ifdef _WIN32
#define CONTAINER _TEXT("test")
#else
// #define CONTAINER _TEXT("\\\\.\\HDIMAGE\\test")
// #define CONTAINER _TEXT("\\\\.\\HDIMAGE\\cbr")
#define CONTAINER _TEXT("\\\\.\\HDIMAGE\\cbr2")
#endif
static void HandleError(char *s);
static void CleanUp(void);

static HCRYPTPROV hProv = 0;
static HCRYPTHASH hHash = 0;
static HCRYPTKEY hKey = 0;
static HCRYPTKEY hPubKey = 0;
static BYTE *pbHash = NULL;
static BYTE *pbSignature = NULL;
static BYTE *pbKeyBlob = NULL;

int main(void)
{
    //-------------------------------------------------------------
    // Объявление и инициализация переменных.

    BYTE *pbBuffer = (BYTE *)"The data that is to be hashed and signed.";
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);
    DWORD dwSigLen;
    DWORD dwBlobLen;
    DWORD cbHash;
    FILE *signature;

    // Получение дескриптора контекста криптографического провайдера.
    if (CryptAcquireContext(
            &hProv,
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
    //--------------------------------------------------------------------
    // Получение открытого ключа подписи. Этот открытый ключ будет
    // использоваться получателем хэша для проверки подписи.
    // В случае, когда получатель имеет доступ к открытому ключю
    // отправителя с помощью сертификата, этот шаг не нужен.

    if (CryptGetUserKey(
            hProv,
            AT_SIGNATURE,
            &hKey))
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
            hKey,
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

    pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    if (!pbKeyBlob)
        HandleError("Out of memory. \n");

    // Сам экспорт в ключевой BLOB.
    if (CryptExportKey(
            hKey,
            0,
            PUBLICKEYBLOB,
            0,
            pbKeyBlob,
            &dwBlobLen))
    {
        printf("Contents have been written to the BLOB. \n");
    }
    else
    {
        HandleError("Error during CryptExportKey.");
    }
    //--------------------------------------------------------------------
    // Создание объекта функции хэширования.

    if (CryptCreateHash(
            hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &hHash))
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

    if (CryptGetHashParam(hHash,
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

    pbHash = (BYTE *)malloc(cbHash);
    if (!pbHash)
        HandleError("Out of memory. \n");

    // Копирование параметра HP_OID в pbHash.
    if (CryptGetHashParam(hHash,
                          HP_OID,
                          pbHash,
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
            hHash,
            pbBuffer,
            dwBufferLen,
            0))
    {
        printf("The data buffer has been hashed.\nHash is : %lld\n", hHash);
    }
    else
    {
        HandleError("Error during CryptHashData.");
    }

    // Определение размера подписи и распределение памяти.
    dwSigLen = 0;
    if (CryptSignHash(
            hHash,
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

    pbSignature = (BYTE *)malloc(dwSigLen);
    if (!pbSignature)
        HandleError("Out of memory.");

    // Подпись объекта функции хэширования.
    if (CryptSignHash(
            hHash,
            AT_SIGNATURE,
            NULL,
            0,
            pbSignature,
            &dwSigLen))
    {
        printf("pbSignature is the hash signature.\n");
    }
    else
    {
        HandleError("Error during CryptSignHash.");
    }

    //if(!fopen_s(&signature, "signature.txt", "w+b" ))
    if (!(signature = fopen("signature.txt", "w+b")))
        HandleError("Problem opening the file signature.txt\n");

    fwrite(pbSignature, 1, dwSigLen, signature);
    fclose(signature);

    // Уничтожение объекта функции хэширования.
    if (hHash)
        CryptDestroyHash(hHash);

    printf("The hash object has been destroyed.\n");
    printf("The signing phase of this program is completed.\n\n");

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

    if (CryptImportKey(
            hProv,
            pbKeyBlob,
            dwBlobLen,
            0,
            0,
            &hPubKey))
    {
        printf("The key has been imported.\n");
    }
    else
    {
        HandleError("Public key import failed.");
    }
    //--------------------------------------------------------------------
    // Создание нового объекта функции хэширования.

    if (CryptCreateHash(
            hProv,
            CALG_GR3411_2012_256,
            0,
            0,
            &hHash))
    {
        printf("The hash object has been recreated. \n");
    }
    else
    {
        HandleError("Error during CryptCreateHash.");
    }

    //--------------------------------------------------------------------
    // Вычисление криптографического хэша буфера.

    if (CryptHashData(
            hHash,
            pbBuffer,
            dwBufferLen,
            0))
    {
        printf("The new has been created.\n");
    }
    else
    {
        HandleError("Error during CryptHashData.");
    }
    //--------------------------------------------------------------------
    // Проверка цифровой подписи.

    if (CryptVerifySignature(
            hHash,
            pbSignature,
            dwSigLen,
            hPubKey,
            NULL,
            0))
    {
        printf("The signature has been verified.\n");
    }
    else
    {
        printf("Signature not validated!\n");
    }

    CleanUp();
    return 0;
}

void CleanUp(void)
{
    if (pbSignature)
        free(pbSignature);
    if (pbHash)
        free(pbHash);
    if (pbKeyBlob)
        free(pbKeyBlob);

    // Уничтожение объекта функции хэширования.
    if (hHash)
        CryptDestroyHash(hHash);

    if (hKey)
        CryptDestroyKey(hKey);

    if (hPubKey)
        CryptDestroyKey(hPubKey);

    // Освобождение дескриптора провайдера.
    if (hProv)
        CryptReleaseContext(hProv, 0);
}

// Конец примера
// (не следует удалять данный комментарий, он используется
//  для автоматической сборки документации)

//--------------------------------------------------------------------
//  В этом примере используется функция HandleError, функция обработки
//  простых ошибок, для печати сообщения и выхода из программы.
//  В большинстве приложений эта функция заменяется другой функцией,
//  которая выводит более полное сообщение об ошибке.

void HandleError(char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    CleanUp();
    if (!err)
        err = 1;
    exit(err);
}
