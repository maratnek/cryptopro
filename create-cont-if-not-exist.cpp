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
#else
#include <string.h>
#include <stdlib.h>
#include <CSP_WinDef.h>
#include <CSP_WinCrypt.h>
#endif
#include <WinCryptEx.h>

// Начало примера (не следует удалять данный комментарий, он используется
// для автоматической сборки документации)
//--------------------------------------------------------------------
// Пример создания ключевого контейнера с именем, передаваемым в качестве
// параметра командной строки. Если параметр не указан, то будет создан
// контейнер с именем по умолчанию. В контейнере созданиются два ключа
// (ключ обмена и ключ подписи).
//--------------------------------------------------------------------

static HCRYPTPROV hCryptProv = 0; // Дескриптор контекста  критографического провайдера.
static HCRYPTKEY hKey = 0;		  // Дескриптор открытого/закрытого ключа.

static void CleanUp(void);
static void HandleError(char *s);

int main(int argc, char *argv[])
{
	// Объявление и инициализация переменных.
	LPSTR pszUserName;	 // Буфер для хранения имени  ключевого контейнера.
	DWORD dwUserNameLen; // Длина буфера.
	LPCSTR UserName;	 // Добавленное по выбору имя пользователя
						 // здесь будет использовано как имя
						 // ключевого контейнера (ограничение на 100 символов).

	// Начало выполнения. Получение имени создаваемого контейнера.
	if (argc < 2)
		HandleError(" using: CreatingKeyContainer.exe <container_name>");

	UserName = argv[1];

	//  Для создания нового ключевого контейнера строка второго параметра
	//  заменяется на NULL здесь и при следующем вызове функции:
	if (CryptAcquireContextA(
			&hCryptProv,		// Дескриптор CSP
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
		if (!CryptAcquireContextA(
				&hCryptProv,
				UserName,
				NULL,
				PROV_GOST_2012_256,
				CRYPT_NEWKEYSET))
		{
			HandleError("Could not create a new key container.\n");
		}

		// install pin
		auto pin = "1234";
		if (!CryptSetProvParam(hCryptProv, PP_KEYEXCHANGE_PIN, (LPBYTE)pin, 0 ))
		{
		    printf("CryptSetProvParam(PP_KEYEXCHANGE_PIN,Encryptor) failed: %x\n", GetLastError());
		}
		printf("A new key container has been created.\n");
	}

	// Криптографический контекст с ключевым контейнером доступен. Получение
	// имени ключевого контейнера.
	if (!CryptGetProvParam(
			hCryptProv,		// Дескриптор CSP
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
			hCryptProv,			 // Дескриптор CSP
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
			hCryptProv,	  // Дескриптор CSP
			AT_SIGNATURE, // Спецификация ключа
			&hKey))		  // Дескриптор ключа
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
				hCryptProv,
				AT_SIGNATURE,
				// CALG_DH_GR3410_12_256_EPHEM,
				0,
				&hKey))
		{
			HandleError("Error occurred creating a signature key.\n");
		}
		printf("Created a signature key pair.\n");
	}

	// Получение ключа обмена: AT_KEYEXCHANGE
	if (CryptGetUserKey(
			hCryptProv,
			AT_KEYEXCHANGE,
			&hKey))
	{
		printf("An exchange key exists. \n");
	}
	else
	{
		printf("No exchange key is available.\n");
	}

	CleanUp();

	printf("Everything is okay. A signature key\n");
	printf("pair and an exchange key exist in\n");
	printf("the %s key container.\n", UserName);

	return 0;
}

// Конец примера
// (не следует удалять данный комментарий, он используется
//  для автоматической сборки документации)

void CleanUp(void)
{
	if (hKey)
		CryptDestroyKey(hKey);
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);
}

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
