#include <chrono>
using namespace std::chrono;

#include "threads-utils.h"
auto lamda_multi_thread = l_thread_data<std::function<void(size_t, size_t)>>;

#include "crypto.h"
using namespace crypto;

int main(void)
{
    auto count = 100'000;

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
                           Crypto sign("SignVerify");
                           std::string some_data = "My some data for signing";
                           auto dwSigLen = 0;
                           for (; i < max_count; i++)
                           {
                               auto signature = sign.sign(some_data.c_str());
                               auto pub_key = sign.getPublicKey();
                               if (!sign.verify(some_data.c_str(), signature.second, signature.first, pub_key )) {
                                   throw "Exception bad verify";
                               }
                           }
                       },
                       count);
    auto end = system_clock::now();
    std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count()/1000.0 << std::endl;

    return 0;
}