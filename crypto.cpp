#include "crypto.h"

using namespace crypto;

Crypto::Crypto(std::string const &name)
{
    this->createContainer("\\\\.\\HDIMAGE\\" + name);
}

void Crypto::showHash() const
{
    //--------------------------------------------------------------------
    // Получение параметра объекта функции хэширования.
    static CHAR rgbDigits[] = "0123456789abcdef";
    BYTE rgbHash[GR3411LEN] = {0};
    DWORD cbHash = GR3411LEN;
    if (!CryptGetHashParam(_hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        return;
    }

    printf("GR3411 hash of file is: ");
    for (DWORD i = 0; i < cbHash; i++)
    {
        printf("%c%c", rgbDigits[rgbHash[i] >> 4],
               rgbDigits[rgbHash[i] & 0xf]);
    }
    printf("\n");
}

T_PAIR_BYTE Crypto::hashByte(const char *data)
{
    this->hash(data);
    T_UNIQP_BYTE rgbHash = std::make_unique<BYTE[]>(GR3411LEN);
    DWORD cbHash = GR3411LEN;
    if (!CryptGetHashParam(_hHash, HP_HASHVAL, rgbHash.get(), &cbHash, 0))
    {
        return {std::move(rgbHash), cbHash};
    }

    return {std::move(rgbHash), cbHash};
}

// create container by name
void Crypto::createContainer(std::string const &name)
{
    // Объявление и инициализация переменных.
    LPSTR pszUserName;   // Буфер для хранения имени  ключевого контейнера.
    DWORD dwUserNameLen; // Длина буфера.
    LPCSTR UserName;     // Добавленное по выбору имя пользователя
                         // здесь будет использовано как имя
                         // ключевого контейнера (ограничение на 100 символов).

    // Начало выполнения. Получение имени создаваемого контейнера.
    if (name.empty())
    {
        this->handleError(" using: CreatingKeyContainer.exe <container_name>");
    }

    UserName = name.c_str();

    //  Для создания нового ключевого контейнера строка второго параметра
    //  заменяется на NULL здесь и при следующем вызове функции:
    if (CryptAcquireContext(
            &_hProv,            // Дескриптор CSP
            UserName,           // Имя контейнера
            NULL,               // Использование провайдера по умолчанию
            PROV_GOST_2012_256, // Тип провайдера
            0))                 // Значения флагов
    {
        printf("A cryptcontext with the %s key container has been acquired.\n", UserName);
    }
    else
    {
        // Создание нового контейнера.
        if (!CryptAcquireContext(
                &_hProv,
                UserName,
                NULL,
                PROV_GOST_2012_256,
                CRYPT_NEWKEYSET))
        {
            handleError("Could not create a new key container.\n");
        }
    }

    // install pin
    if (!CryptSetProvParam(_hProv, PP_KEYEXCHANGE_PIN, (LPBYTE)_pin, 0))
    {
        printf("CryptSetProvParam(PP_KEYEXCHANGE_PIN,Encryptor) failed: %x\n", GetLastError());
    }
    printf("A new key container has been created.\n");

    // Криптографический контекст с ключевым контейнером доступен. Получение
    // имени ключевого контейнера.
    if (!CryptGetProvParam(
            _hProv,         // Дескриптор CSP
            PP_CONTAINER,   // Получение имени ключевого контейнера
            NULL,           // Указатель на имя ключевого контейнера
            &dwUserNameLen, // Длина имени
            0))
    {
        // Ошибка получении имени ключевого контейнера
        handleError("error occurred getting the key container name.");
    }

    pszUserName = (char *)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(
            _hProv,              // Дескриптор CSP
            PP_CONTAINER,        // Получение имени ключевого контейнера
            (LPBYTE)pszUserName, // Указатель на имя ключевого контейнера
            &dwUserNameLen,      // Длина имени
            0))
    {
        // Ошибка получении имени ключевого контейнера
        free(pszUserName);
        handleError("error occurred getting the key container name.");
    }
    else
    {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }

    // Контекст с ключевым контейнером доступен,
    // попытка получения дескриптора ключа подписи
    if (CryptGetUserKey(
            _hProv,       // Дескриптор CSP
            AT_SIGNATURE, // Спецификация ключа
            &_hKey))      // Дескриптор ключа
    {
        printf("A signature key is available.\n");
    }
    else
    {
        printf("No signature key is available.\n");

        // Ошибка в том, что контейнер не содержит ключа.
        if (!(GetLastError() == (DWORD)NTE_NO_KEY))
            handleError("An error other than NTE_NO_KEY getting signature key.\n");

        // Создание подписанной ключевой пары.
        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(
                _hProv,
                AT_SIGNATURE,
                // CALG_DH_GR3410_12_256_EPHEM,
                0,
                &_hKey))
        {
            handleError("Error occurred creating a signature key.\n");
        }
        printf("Created a signature key pair.\n");
    }

    // Получение ключа обмена: AT_KEYEXCHANGE
    if (CryptGetUserKey(
            _hProv,
            AT_KEYEXCHANGE,
            &_hKey))
    {
        printf("An exchange key exists. \n");
    }
    else
    {
        printf("No exchange key is available.\n");
    }

    printf("Everything is okay. A signature key\n");
    printf("pair and an exchange key exist in\n");
    printf("the %s key container.\n", UserName);
}

HCRYPTHASH Crypto::hash(const char *data)
{

    BYTE *pbBuffer = (BYTE *)data;
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
        // printf("Hash object created. \n");
    }
    else
    {
        handleError("Error during CryptCreateHash.");
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
        handleError("Error computing BLOB length.");
    }

    if (!_pbHash)
    {
        _pbHash = std::make_unique<BYTE[]>(cbHash);
    }

    if (!_pbHash)
    {
        handleError("Out of memory. \n");
    }
    else
    {
        // Копирование параметра HP_OID в pbHash.
        if (CryptGetHashParam(_hHash,
                              HP_OID,
                              _pbHash.get(),
                              &cbHash,
                              0))
        {
            // printf("Parameters have been written to the pbHash. \n");
        }
        else
        {
            handleError("Error during CryptGetHashParam.");
        }
    }

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
        handleError("Error during CryptHashData.");
    }

    return _hHash;
}

T_SIGN_BYTE Crypto::sign(const char *data)
{
    _hHash = this->hash((char *)data);
    // this->showHash(_hHash);
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
        handleError("Error during CryptSignHash.");
    }
    //--------------------------------------------------------------------
    // Распределение памяти под буфер подписи.
    if (!_pbSignature)
    {
        _pbSignature = std::shared_ptr<BYTE[]>(new BYTE[dwSigLen]);
    }
    if (!_pbSignature)
    {
        handleError("Out of memory.");
    }
    else
    {
        // Подпись объекта функции хэширования.
        if (CryptSignHash(
                _hHash,
                AT_SIGNATURE,
                NULL,
                0,
                _pbSignature.get(),
                &dwSigLen))
        {
            // printf("pbSignature is the hash signature.\n");
        }
        else
        {
            handleError("Error during CryptSignHash.");
        }
    }

    // Уничтожение объекта функции хэширования.
    if (_hHash)
    {
        CryptDestroyHash(_hHash);
    }

    // printf("The hash object has been destroyed.\n");
    // printf("The signing phase of this program is completed.\n\n");

    return {_pbSignature, dwSigLen};
}

T_PUBLIC_KEY Crypto::getPublicKey()
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
        handleError("Error during CryptGetUserKey for signkey.");
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
        handleError("Error computing BLOB length.");
    }
    //--------------------------------------------------------------------
    // Распределение памяти под pbKeyBlob.
    // _pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    // if (!_pbKeyBlob)
    //     _pbKeyBlob = new BYTE[dwBlobLen];
    auto pbKeyBlob = T_SHARP_BYTE(new BYTE[dwBlobLen]);

    if (!pbKeyBlob)
        handleError("Out of memory. \n");

    // Сам экспорт в ключевой BLOB.
    if (CryptExportKey(
            _hKey,
            0,
            PUBLICKEYBLOB,
            0,
            pbKeyBlob.get(),
            &dwBlobLen))
    {
        // printf("Contents have been written to the BLOB. \n");
    }
    else
    {
        handleError("Error during CryptExportKey.");
    }
    return {pbKeyBlob, dwBlobLen};
}

bool Crypto::verify(const char *data, DWORD dwSigLen, T_SIGN pbSignature, T_PUBLIC_KEY pubkey)
{
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
            pubkey.first.get(), // arr
            pubkey.second,      // size
            0,
            0,
            &_hPubKey))
    {
        // printf("The key has been imported.\n");
    }
    else
    {
        handleError("Public key import failed.");
    }
    //--------------------------------------------------------------------
    // Проверка цифровой подписи.
    // Вычисление криптографического хэша буфера.
    _hHash = this->hash((char *)pbBuffer);

    if (CryptVerifySignature(
            _hHash,
            pbSignature.get(),
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

void Crypto::loadCertificate(const char *filename) {

}


void Crypto::LoadPublicKey(BYTE *pbBlob, DWORD *pcbBlob, char *szCertFile, char *szKeyFile)
{
    static FILE *certf = NULL;                // Файл, в котором хранится сертификат
    // Открытие файла, в котором содержится открытый ключ получателя.
    // if(fopen_s(&certf, szCertFile, "r+b" ))
    if ((certf = fopen(szCertFile, "rb")))
    {
        DWORD cbCert = 2000;
        BYTE pbCert[2000];
        PCCERT_CONTEXT pCertContext = NULL;
        HCRYPTKEY hPubKey;
        printf("The file '%s' was opened\n", szCertFile);

        cbCert = (DWORD)fread(pbCert, 1, cbCert, certf);
        if (!cbCert)
            handleError("Failed to read certificate\n");
        printf("Certificate was read from the '%s'\n", szCertFile);

        pCertContext = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbCert, cbCert);
        if (!pCertContext)
        {
            handleError("CertCreateCertificateContext");
        }

        // Импортируем открытый ключ
        if (CryptImportPublicKeyInfoEx(
                _hProv,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                &(pCertContext->pCertInfo->SubjectPublicKeyInfo),
                0,
                0,
                NULL,
                &hPubKey))
        {
            printf("Public key imported from cert file\n");
        }
        else
        {
            CertFreeCertificateContext(pCertContext);
            handleError("CryptImportPublicKeyInfoEx");
        }
        CertFreeCertificateContext(pCertContext);

        // Экспортируем его в BLOB
        if (CryptExportKey(
                hPubKey,
                0,
                PUBLICKEYBLOB,
                0,
                pbBlob,
                pcbBlob))
        {
            printf("Public key exported to blob\n");
        }
        else
        {
            handleError("CryptExportKey");
        }
    }
//     else
//     {
//         // Открытие файла, в котором содержится открытый ключ получателя.
//         // if(!fopen_s(&publicf, szKeyFile, "r+b" ))
//         // if (!(publicf = fopen(szKeyFile, "rb")))
//         //     handleError("Problem opening the public key blob file\n");
//         // printf("The file '%s' was opened\n", szKeyFile);

//         // *pcbBlob = (DWORD)fread(pbBlob, 1, *pcbBlob, publicf);
//         // if (!*pcbBlob)
//         //     handleError("Failed to read key blob file\n");
//         // printf("Key blob was read from the '%s'\n", szKeyFile);
//     }
}

Crypto::~Crypto()
{
    try
    {
        cleanUp();
    }
    catch (...)
    {
        std::cerr << "Destructor Crypto was failed" << std::endl;
    }
}

void Crypto::cleanUp(void)
{
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

void Crypto::handleError(const char *s)
{
    DWORD err = GetLastError();
    printf("Error number     : 0x%x\n", err);
    printf("Error description: %s\n", s);
    cleanUp();
    if (!err)
        err = 1;
    throw (err);
}
