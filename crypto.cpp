#include "crypto.h"

using namespace crypto;

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
        _pbHash = T_SHARP_BYTE(new BYTE[cbHash]);;
    if (!_pbHash)
        HandleError("Out of memory. \n");

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
        HandleError("Error during CryptGetHashParam.");
    }

    this->InitPubKey();

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
        _pbSignature = T_SHARP_BYTE(new BYTE[dwSigLen]);
    if (!_pbSignature)
        HandleError("Out of memory.");

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
        HandleError("Error during CryptSignHash.");
    }

    // Уничтожение объекта функции хэширования.
    if (_hHash)
        CryptDestroyHash(_hHash);

    // printf("The hash object has been destroyed.\n");
    // printf("The signing phase of this program is completed.\n\n");

    return dwSigLen;
}

void Crypto::InitPubKey()
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
        // printf("Size of the BLOB for the public key determined. \n");
    }
    else
    {
        HandleError("Error computing BLOB length.");
    }
    //--------------------------------------------------------------------
    // Распределение памяти под pbKeyBlob.
    // _pbKeyBlob = (BYTE *)malloc(dwBlobLen);
    // T_SHARP_BYTE p_pub_key = std::make_shared<BYTE[]>(dwBlobLen, 0);
    T_SHARP_BYTE p_pub_key = T_SHARP_BYTE(new BYTE[dwBlobLen]);;

    if (!p_pub_key)
        HandleError("Out of memory. \n");

    // Сам экспорт в ключевой BLOB.
    if (CryptExportKey(
            _hKey,
            0,
            PUBLICKEYBLOB,
            0,
            // _pbKeyBlob,
            p_pub_key.get(),
            &dwBlobLen))
    {
        // printf("Contents have been written to the BLOB. \n");
    }
    else
    {
        HandleError("Error during CryptExportKey.");
    }
    _pub_key = {p_pub_key, dwBlobLen};
}

T_PUBLIC_KEY Crypto::getPublicKey()
{
    return _pub_key;
}


bool Crypto::Verify(const char* data, DWORD dwSigLen, T_PUBLIC_KEY pub_key)
{
    BYTE *pbBuffer = (BYTE *)data;
    DWORD dwBufferLen = (DWORD)(strlen((char *)pbBuffer) + 1);

    DWORD dwBlobLen = pub_key.second;
    auto p_pub_key = pub_key.first;
    
    if (CryptImportKey(
            _hProv,
            p_pub_key.get(),
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
            _pbSignature.get(),
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
    try {
        CleanUp();
    }
    catch (...) {
        std::cerr << "Destructor Crypto was failed" << std::endl;
    }
}


void Crypto::CleanUp(void)
{
    // if (_pbSignature)
    //     delete[] _pbSignature;
    // if (_pbHash)
    //     delete[] _pbHash;
    // if (_pbKeyBlob)
        // delete[] _pbKeyBlob;

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
