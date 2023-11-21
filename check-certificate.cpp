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

int main()
{
    try
    {
        auto count = 10'000;
        Crypto verify("Verify");
        std::string cert_file_name = "./cer-test-clientcont.cer";
        std::string strCertificate = getCertifFromFile(cert_file_name);
        uint verify_count = 0;

        // Start profiling
        // ProfilerStart("./profile_output.prof");

        auto start = system_clock::now();
        for (auto i = 0; i < count; i++)
        {

            // printf("Check certificate!\n");
            if (verify.CheckCertificate(strCertificate))
            {
                verify_count++;
                // printf("Certificate verified!\n");
            }
            else
            {
                // printf("Certificate Unverified!\n");
            }
        }
        // ProfilerStop();
        std::cout << " Verify count: " << verify_count << std::endl;
        auto end = system_clock::now();
        std::cout << "Crypto time is: " << duration_cast<milliseconds>(end - start).count() / 1000.0 << std::endl;
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