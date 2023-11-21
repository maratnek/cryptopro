#include "cryptopro.h"

#include <vector>

#include <fstream>
#include <sstream>
#include <string>

// #include <gperftools/profiler.h>

using namespace crypto;

inline std::string getCertifFromFile(std::string const &filename)
{
    std::ifstream file(filename);

    // Check if the file is open
    if (!file.is_open())
    {
        std::cerr << "Error opening file: " << filename << std::endl;
        throw std::runtime_error("Error opening file: " + filename);
    }

    // Read the file content into a std::string
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string fileContent = buffer.str();

    // Close the file
    file.close();
    return fileContent;
}

#include <chrono>
using namespace std::chrono;

#include "thread-utils.h"
auto lamda_multi_thread = l_thread_data<std::function<void(size_t, size_t)>>;

int main()
{
    try
    {
        auto count = 100'000;
        // Crypto verify("Verify");
        std::string cert_file_name = "./cer-test-clientcont.cer";
        std::string strCertificate = getCertifFromFile(cert_file_name);

        // Start profiling

        auto start = system_clock::now();
        // Crypto verify("Verify");
        // Perform setup here
        // ProfilerStart("./profile_output.prof");
        std::atomic<uint> verify_count = 0;
        lamda_multi_thread([&strCertificate, &verify_count](size_t i, size_t max_count)
                           {
                            Crypto verify("Verify" + std::to_string(i));
                           for (; i < max_count; i++)
                           {
                               if (verify.CheckCertificate(strCertificate))
                               {
                                   verify_count++;
                                //    printf("Certificate verified (separate function)!\n");
                               }
                               else
                               {
                                   printf("Failed: Certificate Unverified!\n");
                               }
                           } },
                           count);
        std::cout << " Verify count: " << verify_count << std::endl;
        // ProfilerStop();
        auto end = system_clock::now();
        std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count() << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }
    catch (...)
    {
        std::cerr << "Unexpected exception" << std::endl;
    }
}