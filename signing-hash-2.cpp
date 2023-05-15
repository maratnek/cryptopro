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
#include <memory>
#include <string>
#include <chrono>
#include <iostream>
#include <vector>
using namespace std::chrono;

#include "verify.hpp"

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
    // struct ContainerData {
        HCRYPTPROV _hProv = 0;
        HCRYPTHASH _hHash = 0;
        HCRYPTKEY _hKey = 0;
        HCRYPTKEY _hPubKey = 0;
    // } _container;

    std::unique_ptr<BYTE[]> _pbHash;
    std::shared_ptr<BYTE[]> _pbSignature;
    // BYTE *_pbSignature = NULL;
    // BYTE *_pbKeyBlob = NULL;

    const char *CONTAINER = "\\\\.\\HDIMAGE\\cbr2";

    const char *_pin = "1234";

    void CleanUp(void);
public:
    Crypto(/* args */);
    Crypto(std::string const& name);
    ~Crypto();

    void createContainer(std::string const& name);

    void HandleError(const char *s);
    HCRYPTHASH hash(const char *data);
    // bool Verify(const char* data, DWORD dwSigLen);
    // bool Verify(const char* data, DWORD dwSigLen, std::shared_ptr<BYTE[]> _pbSignature);
    bool Verify(const char* data, DWORD dwSigLen, std::shared_ptr<BYTE[]> _pbSignature, DWORD dwBlobLen, std::shared_ptr<BYTE[]> _pbKeyBlob);

    std::pair<DWORD, std::shared_ptr<BYTE[]>> Sign(const char* data);
    void showHash(HCRYPTHASH hHash);

    std::pair<DWORD, std::shared_ptr<BYTE[]>> GetPublicKey();
};

void Crypto::showHash(HCRYPTHASH hHash)
{
    BYTE rgbHash[GR3411LEN];
    static DWORD cbHash = GR3411LEN;
    static CHAR rgbDigits[] = "0123456789abcdef";
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(_hProv, 0);
        HandleError("CryptGetHashParam failed");
    }

    printf("GR3411 hash is: ");
    for (int i = 0; i < cbHash; i++)
    {
        printf("%c%c", rgbDigits[rgbHash[i] >> 4],
               rgbDigits[rgbHash[i] & 0xf]);
    }
    printf("\n");
}

Crypto::Crypto(/* args */)
{
    this->createContainer(CONTAINER);
}

Crypto::Crypto(std::string const& name)
{
    this->createContainer("\\\\.\\HDIMAGE\\" + name);
}

// create container by name
void Crypto::createContainer(std::string const& name) 
{
	// Объявление и инициализация переменных.
	LPSTR pszUserName;	 // Буфер для хранения имени  ключевого контейнера.
	DWORD dwUserNameLen; // Длина буфера.
	LPCSTR UserName;	 // Добавленное по выбору имя пользователя
						 // здесь будет использовано как имя
						 // ключевого контейнера (ограничение на 100 символов).

	// Начало выполнения. Получение имени создаваемого контейнера.
	if (name.empty()) {
		HandleError(" using: CreatingKeyContainer.exe <container_name>");
    }

	UserName = name.c_str();

	//  Для создания нового ключевого контейнера строка второго параметра
	//  заменяется на NULL здесь и при следующем вызове функции:
	if (CryptAcquireContext(
			&_hProv,		// Дескриптор CSP
			UserName,			// Имя контейнера
			NULL,				// Использование провайдера по умолчанию
			PROV_GOST_2012_256, // Тип провайдера
			0))					// Значения флагов
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
			HandleError("Could not create a new key container.\n");
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
			_hProv,		// Дескриптор CSP
			PP_CONTAINER,	// Получение имени ключевого контейнера
			NULL,			// Указатель на имя ключевого контейнера
			&dwUserNameLen, // Длина имени
			0))
	{
		// Ошибка получении имени ключевого контейнера
		HandleError("error occurred getting the key container name.");
	}

	pszUserName = (char *)malloc((dwUserNameLen + 1));

	if (!CryptGetProvParam(
			_hProv,			 // Дескриптор CSP
			PP_CONTAINER,		 // Получение имени ключевого контейнера
			(LPBYTE)pszUserName, // Указатель на имя ключевого контейнера
			&dwUserNameLen,		 // Длина имени
			0))
	{
		// Ошибка получении имени ключевого контейнера
		free(pszUserName);
		HandleError("error occurred getting the key container name.");
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
			_hProv,	  // Дескриптор CSP
			AT_SIGNATURE, // Спецификация ключа
			&_hKey))		  // Дескриптор ключа
	{
		printf("A signature key is available.\n");
	}
	else
	{
		printf("No signature key is available.\n");

		// Ошибка в том, что контейнер не содержит ключа.
		if (!(GetLastError() == (DWORD)NTE_NO_KEY))
			HandleError("An error other than NTE_NO_KEY getting signature key.\n");

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
			HandleError("Error occurred creating a signature key.\n");
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

    if (!_pbHash) {
        _pbHash = std::make_unique<BYTE[]>(cbHash);
    }

    if (!_pbHash) {
        HandleError("Out of memory. \n");
    } else {
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
        HandleError("Error during CryptHashData.");
    }

    return _hHash;

}

std::pair<DWORD, std::shared_ptr<BYTE[]>> Crypto::Sign(const char* data)
{
    _hHash = this->hash((char*)data);
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
        HandleError("Error during CryptSignHash.");
    }
    //--------------------------------------------------------------------
    // Распределение памяти под буфер подписи.
    if (!_pbSignature) {
        _pbSignature = std::shared_ptr<BYTE[]>(new BYTE[dwSigLen]);
    }
    // if (!_pbSignature)
        // _pbSignature = new BYTE[dwSigLen]; ;
    if (!_pbSignature) {
        HandleError("Out of memory.");
    } else {
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
    }

    // Уничтожение объекта функции хэширования.
    if (_hHash) {
        CryptDestroyHash(_hHash);
    }

    // printf("The hash object has been destroyed.\n");
    // printf("The signing phase of this program is completed.\n\n");

    return {dwSigLen, _pbSignature};
}

std::pair<DWORD,std::shared_ptr<BYTE[]>> Crypto::GetPublicKey()
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
    // if (!_pbKeyBlob)
    //     _pbKeyBlob = new BYTE[dwBlobLen];
    auto pbKeyBlob = std::shared_ptr<BYTE[]>(new BYTE[dwBlobLen]);

    if (!pbKeyBlob)
        HandleError("Out of memory. \n");

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
        HandleError("Error during CryptExportKey.");
    }
    return {dwBlobLen, pbKeyBlob};

}

bool Crypto::Verify(const char* data, DWORD dwSigLen, std::shared_ptr<BYTE[]> _pbSignature, DWORD dwBlobLen, std::shared_ptr<BYTE[]> _pbKeyBlob)
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
    
    // DWORD dwBlobLen;
    // DWORD cbHash;
    // FILE *signature;

    if (CryptImportKey(
            _hProv,
            _pbKeyBlob.get(),
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

    // this->showHash(_hHash);

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
    CleanUp();
}


void Crypto::CleanUp(void)
{
    // if (_pbSignature)
        // free(_pbSignature);
        // delete[] _pbSignature;
    // if (_pbHash)
        // free(_pbHash);
        // delete[] _pbHash;
    // if (_pbKeyBlob)
        // free(_pbKeyBlob);
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

// Конец примера
// (не следует удалять данный комментарий, он используется
//  для автоматической сборки документации)

//--------------------------------------------------------------------
//  В этом примере используется функция HandleError, функция обработки
//  простых ошибок, для печати сообщения и выхода из программы.
//  В большинстве приложений эта функция заменяется другой функцией,
//  которая выводит более полное сообщение об ошибке.

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

    struct Transaction {
        std::string _some_message;
        std::pair<DWORD, std::shared_ptr<BYTE[]>> _signature;
        std::pair<DWORD, std::shared_ptr<BYTE[]>> _pbKey;
    };

int main(int argc, char **argv)
{
    try{

    Crypto sign("Sign");
    Crypto verify("Verify");
    auto dwSigLen = 0;
    std::string my_new_data_for_sign = "My some data for signing. This is the text.";


    // auto count = 10000;
    // prepare messages
    // std::vector<std::pair<DWORD, std::shared_ptr<BYTE[]> > > signed_messages(count);
    // for (size_t i = 0; i < count; i++)
    // {
    //     signed_messages.push_back(sign.Sign(my_new_data_for_sign.c_str()));
    // }

    // auto start = system_clock::now();
    // for (size_t i = 0; i < count; i++)
    // {
    //     // my_new_data_for_sign += std::to_string(i);
    //     // auto [dwSigLen, pbSignature] = sign.Sign(my_new_data_for_sign.c_str());
    //     auto [dwSigLen, pbSignature] = signed_messages[i];
    //     auto [dbWord, pbKeyBlob] = sign.GetPublicKey();
    //     if( !verify.Verify(my_new_data_for_sign.c_str(), dwSigLen, pbSignature, dbWord, pbKeyBlob) ) {
    //         throw "Exception bad verify";
    //     }
    // }
    // auto end = system_clock::now();
    // std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count()/1000.0 << std::endl;


    // new test 
    // prepare transaction

    auto count = 100000;
    std::vector<Transaction> transactions(count);
    for (size_t i = 0; i < count; i++)
    {
        Transaction tr;
        tr._some_message = "My some data for signing. This is the text.";
        tr._signature = sign.Sign(tr._some_message.c_str());
        tr._pbKey = sign.GetPublicKey();
        transactions[i] = std::move(tr);
    }
    
    // verify transactions

    std::cout << "Starting verify transaction..." << std::endl;
    auto start = system_clock::now();
    for (size_t i = 0; i < count; i++)
    {
        auto tr = transactions[i];
        // std::cout << "Transaction " << tr._some_message << std::endl;
        if( !verify.Verify(tr._some_message.c_str(), tr._signature.first, tr._signature.second, tr._pbKey.first, tr._pbKey.second) ) {
            throw "Exception bad verify";
        }
    }
    auto end = system_clock::now();
    std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count()/1000.0 << std::endl;


    }
    catch (char const* exception){
        std::cerr << argv[0] << " Exception: " << exception << std::endl;
    }
    catch (...){
        std::cerr << argv[0] << " Some exception. " << std::endl;
    }
    return 0;
}