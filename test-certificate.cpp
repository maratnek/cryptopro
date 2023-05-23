#include "crypto.h"

#include <vector>

using namespace crypto;

#include <chrono>
using namespace std::chrono;

/// multithread libs
#include "threads-utils.h"
auto lamda_multi_thread = l_thread_data<std::function<void(size_t, size_t)>>;
////////////////////////////////

struct Transaction
{
    std::string _some_message;
    T_SIGN_BYTE _signature;
    T_PUBLIC_KEY _pbKey;
};

int main(int argc, char **argv)
{
    try
    {
        // prepare test
        // Crypto sign("Sign");
        // Crypto verify("Verify");
        auto dwSigLen = 0;

        auto count = 1000'000;
        std::cout << "Count of " << count << "\n";
        std::vector<Transaction> transactions(count);

        {
            auto start = system_clock::now();
            lamda_multi_thread([&transactions](size_t i, size_t max_count)
                               {
                                Crypto sign("Sign_" + std::to_string(max_count));
                                for (; i < max_count; i++)
                                {
                                    Transaction tr;
                                    tr._some_message = "My some data for signing. This is the text.";
                                    try
                                    {
                                    tr._signature = sign.sign(tr._some_message.c_str());
                                    tr._pbKey = sign.getPublicKey();
                                    }
                                    catch(int e){
                                        std::cerr << "Sign problem: " << e << '\n';
                                    }
                                    catch(...){
                                        std::cerr << "Sign problem: " << '\n';
                                    }
                                    
                                    transactions[i] = tr;
                                } },
                               count);
            auto end = system_clock::now();
            std::cout << "Prepare Crypto time is: " << duration_cast<milliseconds>(end - start).count() / 1000.0 << std::endl;
        }

        // verify transactions
        std::cout << "Starting verify transaction..." << std::endl;

        auto start = system_clock::now();
        std::atomic_int realTrCount = 0;
        lamda_multi_thread([&transactions, &realTrCount](size_t i, size_t max_count)
                           {
                                Crypto verify("Verify_" + std::to_string(max_count));
                                // Crypto verify("Verify");
                                int tCount = 0;
                                for (; i < max_count; i++)
                                {
                                    auto tr = transactions[i];
                                    ++tCount;
                                    try
                                    {
                                        if (!verify.verify(tr._some_message.c_str(), tr._signature.second, tr._signature.first, tr._pbKey)){
                                            throw "Exception bad verify";
                                        }
                                    }
                                    catch(int e){
                                        std::cerr << "Verify problem: " << e << '\n';
                                    }
                                    catch(...){
                                        std::cerr << "Verify problem: " << '\n';
                                    }
                                } 

                                    realTrCount += tCount;
                                },
                           count);
        auto end = system_clock::now();
        std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count() / 1000.0 << std::endl;
        auto tps = realTrCount / (duration_cast<milliseconds>(end - start).count() / 1000.0);
        std::cout << "TPS is: " << tps << " " << realTrCount << std::endl;
    }
    catch (char const *exception)
    {
        std::cerr << argv[0] << " Exception: " << exception << std::endl;
    }
    catch (...)
    {
        std::cerr << argv[0] << " Some exception. " << std::endl;
    }
    return 0;
}