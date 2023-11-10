#include "crypto.h"

#include <vector>

using namespace crypto;

#include <chrono>
using namespace std::chrono;

/// multithread libs
#include "threads-utils.h"
auto lamda_multi_thread = l_thread_data<std::function<void(size_t, size_t)>>;
////////////////////////////////
#define MAX_PUBLICKEYBLOB_SIZE 200

int main() {
    try
    {
        T_SIGN_BYTE _signature;
        T_PUBLIC_KEY _pbKey;
        std::string _some_message = "Some test to sign";

        BYTE pbKeyBlob[MAX_PUBLICKEYBLOB_SIZE];   // Указатель на ключевой BLOB
        DWORD dwBlobLen = MAX_PUBLICKEYBLOB_SIZE; // Длина ключевого BLOBа
        // sender side
        {
            Crypto sign("Sign");
            _signature = sign.sign(_some_message.c_str());
            _pbKey = sign.getPublicKey();
        }
        std::string cert_file_name = "cert-for-del.cer";
        {
            Crypto verify("Verify");
            verify.LoadPublicKey(pbKeyBlob, &dwBlobLen, cert_file_name.c_str(), nullptr);
            std::cout << "cert file loaded" << std::endl;
            T_PUBLIC_KEY pbKey(pbKeyBlob, dwBlobLen);
            if (verify.verify(_some_message.c_str(), _signature.second, _signature.first, _pbKey)){
                std::cout << "verified message" << std::endl;
            } else {
                std::cout << "unverified message" << std::endl;
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}