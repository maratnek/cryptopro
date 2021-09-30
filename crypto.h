#pragma once

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

namespace crypto
{
    using T_UNIQP_BYTE = std::unique_ptr<BYTE[]>;
    using T_SHARP_BYTE = std::shared_ptr<BYTE[]>;
    using T_PAIR_BYTE = std::pair<T_UNIQP_BYTE, DWORD>;
    // using T_HASH = std::pair<T_SHARP_BYTE, DWORD>;
    // using T_SIGN = std::pair<T_SHARP_BYTE, DWORD>;
    using T_HASH = T_SHARP_BYTE;
    using T_SIGN = T_SHARP_BYTE;

    using T_PUBLIC_KEY = std::pair<T_SHARP_BYTE, DWORD>;

    constexpr size_t GR3411LEN = 64;
    class Crypto
    {
    private:
        /* data */
        HCRYPTPROV _hProv = 0;
        HCRYPTHASH _hHash = 0;
        HCRYPTKEY _hKey = 0;
        HCRYPTKEY _hPubKey = 0;
        T_HASH _pbHash;
        T_SIGN _pbSignature;
        T_PUBLIC_KEY _pub_key;

        // TODO for test using only one container (prod need more)
        const char *CONTAINER = "\\\\.\\HDIMAGE\\cbr2";

        void InitPubKey();

    public:
        Crypto(/* args */);
        ~Crypto();
        void CleanUp(void);

        T_PUBLIC_KEY getPublicKey();
        void HandleError(const char *s);
        HCRYPTHASH hash(const char *data);
        T_PAIR_BYTE hash_byte(const char *data);
        bool Verify(const char *data, DWORD dwSigLen, T_PUBLIC_KEY pub_key);
        DWORD Sign(const char *data);
        void showHash() const;
    };

} // end namespace