#include <iostream>
#include <openssl/ssl.h>

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Get the OpenSSL version string and print it
    std::cout << "OpenSSL Test Successful! " << std::endl;
    std::cout << "OpenSSL Version: " << OpenSSL_version(SSLEAY_VERSION) << std::endl;

    // A simple, non-OpenSSL function call to confirm the program runs
    int a = 5;
    int b = 10;
    std::cout << "Arithmetic Check: " << a + b << std::endl;

    return 0;
}
