#include "cryptopro.h"

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

        // sender side
        {
            Crypto sign("clientcont");
            _signature = sign.sign(_some_message.c_str());
            _pbKey = sign.getPublicKey();

            printf("Show public key\n");
            static CHAR rgbDigits[] = "0123456789ABCDEF";
            for (DWORD i = 0; i < _pbKey.second; i++)
            {
                printf("%c%c", rgbDigits[_pbKey.first[i] >> 4],
                       rgbDigits[_pbKey.first[i] & 0xf]);
            }
            printf("\n");
        }
        std::string cert_file_name = "./cer-test-clientcont.cer";
        {
            Crypto verify("Verify");
            DWORD dwBlobLen = MAX_PUBLICKEYBLOB_SIZE; // Длина ключевого BLOBа
            auto pbKeyBlob = T_SHARP_BYTE(new BYTE[dwBlobLen]);

            printf("Check certificate!\n");
            // std::string cr_file_name = "./rootca.cer";
            // std::string cr_file_name = "./cer-test-mycont.cer";
            if (verify.CheckCertificate(cert_file_name.c_str())) {
                printf("Certificate verified!\n");

                verify.LoadPublicKey(pbKeyBlob.get(), &dwBlobLen, cert_file_name.c_str());
                std::cout << "cert file loaded" << std::endl;
                T_PUBLIC_KEY pbKey(pbKeyBlob, dwBlobLen);
                printf("Cert blob len %d\n", pbKey.second);

                printf("Show public key from certificate\n");
                static CHAR rgbDigits[] = "0123456789ABCDEF";
                for (DWORD i = 0; i < pbKey.second; i++)
                {
                    printf("%c%c", rgbDigits[pbKey.first[i] >> 4],
                           rgbDigits[pbKey.first[i] & 0xf]);
                }
                printf("\n");

                if (verify.verify(_some_message.c_str(), _signature.second, _signature.first, pbKey))
                {
                    // if (verify.verify(_some_message.c_str(), _signature.second, _signature.first, _pbKey)){
                    std::cout << "verified message" << std::endl;
                }
                else
                {
                    std::cout << "unverified message" << std::endl;
                }

            } else {
                printf("Certificate Unverified!\n");
            }



        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    
}