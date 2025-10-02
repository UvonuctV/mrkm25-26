// Disable Windows min/max macros that conflict with GMP
#define NOMINMAX
#ifdef _WIN32
    #include <windows.h>
#endif

// GMP library with MSVC warning suppressions
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4146) // unary minus operator applied to unsigned type
#pragma warning(disable: 4244) // conversion from 'mp_limb_t' to 'unsigned long'
#pragma warning(disable: 4267) // conversion from 'size_t' to 'int'
#pragma warning(disable: 4800) // forcing value to bool
#pragma warning(disable: 4018) // signed/unsigned mismatch
#pragma warning(disable: 4309)  // Disable "truncation of constant value"
#endif

#include <gmp.h> 

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <cstring>
#include <ctime>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <random>
#include <thread>
#include <algorithm>
#include <numeric>
#include <mutex>
#include <atomic>
#include <iomanip>
using namespace std;

// Function prototypes
void demo_initialization();
void demo_basic_arithmetic();
void demo_multiplication_algorithms();
void demo_division_operations();
void demo_modular_arithmetic();
void demo_number_theoretic();
void demo_bitwise_operations();
void demo_comparison_operations();
void demo_parallel_scenario();
void print_separator(const char* title);

int main() {
    cout << "==================================================" << endl;
    cout << "  GNU GMP Multi-Precision Arithmetic Demo" << endl;
    cout << "  64-bit Architecture Demonstration" << endl;
    cout << "==================================================" << endl;
    cout << endl;

    demo_initialization();
    demo_basic_arithmetic();
    demo_multiplication_algorithms();
    demo_division_operations();
    demo_modular_arithmetic();
    demo_number_theoretic();
    demo_bitwise_operations();
    demo_comparison_operations();
    demo_parallel_scenario();

    cout << "\n==================================================" << endl;
    cout << "  All demonstrations completed successfully!" << endl;
    cout << "==================================================" << endl;

    return 0;
}

void print_separator(const char* title) {
    cout << "\n--------------------------------------------------" << endl;
    cout << "  " << title << endl;
    cout << "--------------------------------------------------" << endl;
}

void demo_initialization() {
    print_separator("1. INITIALIZATION AND ASSIGNMENT");

    // mpz_init - Initialize integer variable
    mpz_t x;
    mpz_init(x);
    cout << "After mpz_init(x): ";
    gmp_printf("%Zd\n", x);

    // mpz_set - Set from another mpz_t
    mpz_t y;
    mpz_init(y);
    mpz_set_ui(x, 12345);
    mpz_set(y, x);
    cout << "After mpz_set(y, x) where x=12345: ";
    gmp_printf("y = %Zd\n", y);

    // mpz_set_str - Set from string
    mpz_t large_num;
    mpz_init(large_num);
    mpz_set_str(large_num, "123456789012345678901234567890", 10);
    cout << "Large number from string: ";
    gmp_printf("%Zd\n", large_num);

    // mpz_init2 - Initialize with pre-allocated space
    mpz_t preallocated;
    mpz_init2(preallocated, 2048); // Reserve space for 2048 bits
    cout << "Pre-allocated variable for 2048 bits created\n";

    // Cleanup
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(large_num);
    mpz_clear(preallocated);
}

void demo_basic_arithmetic() {
    print_separator("2. BASIC ARITHMETIC OPERATIONS");

    mpz_t a, b, result;
    mpz_init(a);
    mpz_init(b);
    mpz_init(result);

    // Set test values
    mpz_set_str(a, "999999999999999999", 10);
    mpz_set_str(b, "888888888888888888", 10);

    // Addition: mpz_add
    mpz_add(result, a, b);
    cout << "Addition:" << endl;
    gmp_printf("  %Zd + %Zd = %Zd\n", a, b, result);

    // Subtraction: mpz_sub
    mpz_sub(result, a, b);
    cout << "Subtraction:" << endl;
    gmp_printf("  %Zd - %Zd = %Zd\n", a, b, result);

    // Multiplication: mpz_mul
    mpz_mul(result, a, b);
    cout << "Multiplication:" << endl;
    gmp_printf("  %Zd x %Zd = %Zd\n", a, b, result);

    // Test with small numbers to show carry propagation
    mpz_set_ui(a, 18446744073709551615UL); // Max 64-bit value
    mpz_set_ui(b, 2);
    mpz_add(result, a, b);
    cout << "\nCarry propagation example:" << endl;
    gmp_printf("  %Zd + %Zd = %Zd\n", a, b, result);

    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(result);
}

void demo_multiplication_algorithms() {
    print_separator("3. MULTIPLICATION WITH DIFFERENT SIZES");

    mpz_t small1, small2, medium1, medium2, large1, large2, result;
    mpz_init(small1);
    mpz_init(small2);
    mpz_init(medium1);
    mpz_init(medium2);
    mpz_init(large1);
    mpz_init(large2);
    mpz_init(result);

    // Small operands (basecase multiplication)
    mpz_set_ui(small1, 123456);
    mpz_set_ui(small2, 789012);
    clock_t start = clock();
    mpz_mul(result, small1, small2);
    clock_t end = clock();
    double time_small = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000000.0;;
    cout << "Small multiplication (basecase):" << endl;
    gmp_printf("  %Zd x %Zd = %Zd\n", small1, small2, result);
    printf("  Time: %.2f microseconds\n", time_small);

    // Medium operands (Karatsuba)
    mpz_set_str(medium1, "123456789012345678901234567890", 10);
    mpz_set_str(medium2, "987654321098765432109876543210", 10);
    start = clock();
    mpz_mul(result, medium1, medium2);
    end = clock();
    double time_medium = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000000.0;
    cout << "\nMedium multiplication (Karatsuba):" << endl;
    gmp_printf("  Result has %zu bits\n", mpz_sizeinbase(result, 2));
    printf("  Time: %.2f microseconds\n", time_medium);

    // Large operands (Toom-Cook or FFT)
    mpz_ui_pow_ui(large1, 2, 512);
    mpz_add_ui(large1, large1, 12345);
    mpz_ui_pow_ui(large2, 2, 512);
    mpz_add_ui(large2, large2, 67890);
    start = clock();
    mpz_mul(result, large1, large2);
    end = clock();
    double time_large = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000000.0;
    cout << "\nLarge multiplication (Toom-Cook/FFT):" << endl;
    gmp_printf("  Result has %zu bits\n", mpz_sizeinbase(result, 2));
    printf("  Time: %.2f microseconds\n", time_large);

    mpz_clear(small1);
    mpz_clear(small2);
    mpz_clear(medium1);
    mpz_clear(medium2);
    mpz_clear(large1);
    mpz_clear(large2);
    mpz_clear(result);
}

void demo_division_operations() {
    print_separator("4. DIVISION OPERATIONS");

    mpz_t n, d, q, r;
    mpz_init(n);
    mpz_init(d);
    mpz_init(q);
    mpz_init(r);

    // Set dividend and divisor
    mpz_set_str(n, "123456789012345678901234567890", 10);
    mpz_set_ui(d, 7);

    // mpz_tdiv_q - Truncated division quotient
    mpz_tdiv_q(q, n, d);
    cout << "Truncated division (quotient only):" << endl;
    gmp_printf("  %Zd / %Zd = %Zd\n", n, d, q);

    // mpz_tdiv_r - Truncated division remainder
    mpz_tdiv_r(r, n, d);
    cout << "Truncated division (remainder only):" << endl;
    gmp_printf("  %Zd mod %Zd = %Zd\n", n, d, r);

    // mpz_tdiv_qr - Both quotient and remainder
    mpz_tdiv_qr(q, r, n, d);
    cout << "Truncated division (both):" << endl;
    gmp_printf("  %Zd = %Zd x %Zd + %Zd\n", n, d, q, r);

    // Verification
    mpz_t verify;
    mpz_init(verify);
    mpz_mul(verify, d, q);
    mpz_add(verify, verify, r);
    cout << "Verification: ";
    if (mpz_cmp(verify, n) == 0) {
        cout << "PASSED" << endl;
    }
    else {
        cout << "FAILED" << endl;
    }

    mpz_clear(n);
    mpz_clear(d);
    mpz_clear(q);
    mpz_clear(r);
    mpz_clear(verify);
}

void demo_modular_arithmetic() {
    print_separator("5. MODULAR ARITHMETIC");

    mpz_t a, b, mod, result;
    mpz_init(a);
    mpz_init(b);
    mpz_init(mod);
    mpz_init(result);

    // Setup values
    mpz_set_ui(a, 12345);
    mpz_set_ui(b, 67890);
    mpz_set_ui(mod, 97); // Prime modulus

    // mpz_mod - Modular reduction
    mpz_mod(result, a, mod);
    cout << "Modular reduction:" << endl;
    gmp_printf("  %Zd mod %Zd = %Zd\n", a, mod, result);

    // mpz_powm - Modular exponentiation
    clock_t start = clock();
    mpz_powm(result, a, b, mod);
    clock_t end = clock();
    double time_powm = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000000.0;;
    cout << "\nModular exponentiation:" << endl;
    gmp_printf("  %Zd^%Zd mod %Zd = %Zd\n", a, b, mod, result);
    printf("  Time: %.2f microseconds\n", time_powm);

    // Larger example for RSA-like operation
    mpz_set_str(a, "123456789012345678901234567890", 10);
    mpz_ui_pow_ui(mod, 2, 128);
    mpz_nextprime(mod, mod); // Get a prime near 2^128
    mpz_set_ui(b, 65537); // Common RSA exponent

    start = clock();
    mpz_powm(result, a, b, mod);
    end = clock();
    time_powm = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000.0;
    cout << "\nRSA-like modular exponentiation (128-bit modulus):" << endl;
    gmp_printf("  Base has %zu bits\n", mpz_sizeinbase(a, 2));
    gmp_printf("  Modulus has %zu bits\n", mpz_sizeinbase(mod, 2));
    gmp_printf("  Result: %Zd\n", result);
    printf("  Time: %.3f milliseconds\n", time_powm);

    // mpz_invert - Modular multiplicative inverse
    mpz_set_ui(a, 17);
    mpz_set_ui(mod, 43);
    int invertible = mpz_invert(result, a, mod);
    cout << "\nModular multiplicative inverse:" << endl;
    gmp_printf("  %Zd^(-1) mod %Zd = ", a, mod);
    if (invertible) {
        gmp_printf("%Zd\n", result);
        // Verify: a * result ≡ 1 (mod mod)
        mpz_t verify;
        mpz_init(verify);
        mpz_mul(verify, a, result);
        mpz_mod(verify, verify, mod);
        cout << "  Verification: ";
        if (mpz_cmp_ui(verify, 1) == 0) {
            cout << "PASSED" << endl;
        }
        else {
            cout << "FAILED" << endl;
        }
        mpz_clear(verify);
    }
    else {
        cout << "does not exist" << endl;
    }

    // Test case where inverse doesn't exist
    mpz_set_ui(a, 6);
    mpz_set_ui(mod, 9);
    invertible = mpz_invert(result, a, mod);
    cout << "\nInverse that doesn't exist:" << endl;
    gmp_printf("  %Zd^(-1) mod %Zd = ", a, mod);
    if (invertible) {
        gmp_printf("%Zd\n", result);
    }
    else {
        cout << "does not exist (gcd != 1)" << endl;
    }

    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(mod);
    mpz_clear(result);
}

void demo_number_theoretic() {
    print_separator("6. NUMBER-THEORETIC FUNCTIONS");

    mpz_t a, b, result;
    mpz_init(a);
    mpz_init(b);
    mpz_init(result);

    // mpz_gcd - Greatest Common Divisor
    mpz_set_ui(a, 48);
    mpz_set_ui(b, 18);
    mpz_gcd(result, a, b);
    cout << "Greatest Common Divisor (Euclidean Algorithm):" << endl;
    gmp_printf("  gcd(%Zd, %Zd) = %Zd\n", a, b, result);

    // GCD with large numbers
    mpz_set_str(a, "123456789012345678901234567890", 10);
    mpz_set_str(b, "987654321098765432109876543210", 10);
    clock_t start = clock();
    mpz_gcd(result, a, b);
    clock_t end = clock();
    double time_gcd = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000000.0;
    cout << "\nGCD with large numbers:" << endl;
    gmp_printf("  Result: %Zd\n", result);
    printf("  Time: %.2f microseconds\n", time_gcd);

    // mpz_probab_prime_p - Primality testing
    cout << "\nPrimality Testing (Miller-Rabin):" << endl;

    mpz_set_ui(a, 97);
    int prime_result = mpz_probab_prime_p(a, 25);
    gmp_printf("  %Zd is ", a);
    if (prime_result == 2) cout << "definitely prime" << endl;
    else if (prime_result == 1) cout << "probably prime" << endl;
    else cout << "composite" << endl;

    mpz_set_ui(a, 100);
    prime_result = mpz_probab_prime_p(a, 25);
    gmp_printf("  %Zd is ", a);
    if (prime_result == 2) cout << "definitely prime" << endl;
    else if (prime_result == 1) cout << "probably prime" << endl;
    else cout << "composite" << endl;

    // Large prime testing
    mpz_set_str(a, "170141183460469231731687303715884105727", 10); // 2^127 - 1 (Mersenne prime)
    start = clock();
    prime_result = mpz_probab_prime_p(a, 25);
    end = clock();
    double time_prime = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000.0;
    gmp_printf("  %Zd (%zu bits) is ", a, mpz_sizeinbase(a, 2));
    if (prime_result == 2) cout << "definitely prime" << endl;
    else if (prime_result == 1) cout << "probably prime" << endl;
    else cout << "composite" << endl;
    printf("  Time: %.3f milliseconds\n", time_prime);

    // Generate next prime
    mpz_set_ui(a, 1000);
    mpz_nextprime(result, a);
    cout << "\nNext prime after 1000:" << endl;
    gmp_printf("  %Zd\n", result);

    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(result);
}

void demo_bitwise_operations() {
    print_separator("7. BITWISE AND LOGICAL OPERATIONS");

    mpz_t a, b, result;
    mpz_init(a);
    mpz_init(b);
    mpz_init(result);

    mpz_set_ui(a, 0xF0F0); // 1111000011110000 in binary
    mpz_set_ui(b, 0xFF00); // 1111111100000000 in binary

    // mpz_and - Bitwise AND
    mpz_and(result, a, b);
    cout << "Bitwise AND:" << endl;
    gmp_printf("  0x%Zx & 0x%Zx = 0x%Zx\n", a, b, result);

    // mpz_ior - Bitwise OR
    mpz_ior(result, a, b);
    cout << "Bitwise OR:" << endl;
    gmp_printf("  0x%Zx | 0x%Zx = 0x%Zx\n", a, b, result);

    // mpz_xor - Bitwise XOR
    mpz_xor(result, a, b);
    cout << "Bitwise XOR:" << endl;
    gmp_printf("  0x%Zx ^ 0x%Zx = 0x%Zx\n", a, b, result);

    // mpz_popcount - Population count (number of 1-bits)
    mpz_set_ui(a, 0xFFFF);
    mp_bitcnt_t popcount = mpz_popcount(a);
    cout << "\nPopulation count (number of 1-bits):" << endl;
    gmp_printf("  popcount(0x%Zx) = %lu\n", a, popcount);

    // Large number popcount
    mpz_ui_pow_ui(a, 2, 100);
    mpz_sub_ui(a, a, 1); // 2^100 - 1 (all 1's)
    popcount = mpz_popcount(a);
    cout << "\nLarge number popcount:" << endl;
    gmp_printf("  popcount(2^100 - 1) = %lu bits\n", popcount);

    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(result);
}

void demo_comparison_operations() {
    print_separator("8. COMPARISON OPERATIONS");

    mpz_t a, b;
    mpz_init(a);
    mpz_init(b);

    mpz_set_ui(a, 12345);
    mpz_set_ui(b, 67890);

    // mpz_cmp - Compare two integers
    int cmp_result = mpz_cmp(a, b);
    cout << "Comparison operations:" << endl;
    gmp_printf("  %Zd compared to %Zd: ", a, b);
    if (cmp_result < 0) cout << "less than" << endl;
    else if (cmp_result == 0) cout << "equal" << endl;
    else cout << "greater than" << endl;

    // mpz_cmp_ui - Compare with unsigned long
    cmp_result = mpz_cmp_ui(a, 10000);
    gmp_printf("  %Zd compared to 10000: ", a);
    if (cmp_result < 0) cout << "less than" << endl;
    else if (cmp_result == 0) cout << "equal" << endl;
    else cout << "greater than" << endl;

    // mpz_sgn - Sign of integer
    mpz_set_si(a, -500);
    int sign = mpz_sgn(a);
    gmp_printf("  Sign of %Zd: ", a);
    if (sign < 0) cout << "negative" << endl;
    else if (sign == 0) cout << "zero" << endl;
    else cout << "positive" << endl;

    mpz_set_ui(a, 0);
    sign = mpz_sgn(a);
    gmp_printf("  Sign of %Zd: ", a);
    if (sign < 0) cout << "negative" << endl;
    else if (sign == 0) cout << "zero" << endl;
    else cout << "positive" << endl;

    // Size in base
    mpz_set_str(a, "123456789012345678901234567890", 10);
    size_t size_dec = mpz_sizeinbase(a, 10);
    size_t size_bin = mpz_sizeinbase(a, 2);
    size_t size_hex = mpz_sizeinbase(a, 16);
    cout << "\nSize in different bases:" << endl;
    gmp_printf("  Number: %Zd\n", a);
    printf("  Decimal digits: %zu\n", size_dec);
    printf("  Binary digits: %zu\n", size_bin);
    printf("  Hexadecimal digits: %zu\n", size_hex);

    mpz_clear(a);
    mpz_clear(b);
}

void demo_parallel_scenario() {
    print_separator("9. PARALLEL COMPUTING SCENARIO SIMULATION");

    cout << "Simulating independent cryptographic operations..." << endl;
    cout << "(In real parallel code, these would run on separate threads)\n" << endl;

    const int NUM_OPERATIONS = 5;
    mpz_t base[NUM_OPERATIONS];
    mpz_t exponent[NUM_OPERATIONS];
    mpz_t modulus[NUM_OPERATIONS];
    mpz_t result[NUM_OPERATIONS];

    // Initialize all variables
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        mpz_init(base[i]);
        mpz_init(exponent[i]);
        mpz_init(modulus[i]);
        mpz_init(result[i]);
    }

    // Setup different operations (simulating different transactions)
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        mpz_set_ui(base[i], 1000 + i * 100);
        mpz_set_ui(exponent[i], 65537); // Common RSA exponent
        mpz_ui_pow_ui(modulus[i], 2, 64);
        mpz_nextprime(modulus[i], modulus[i]);
    }

    // Perform operations and measure time
    clock_t total_start = clock();
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        clock_t start = clock();
        mpz_powm(result[i], base[i], exponent[i], modulus[i]);
        clock_t end = clock();
        double time_op = (static_cast<double>(end) - static_cast<double>(start)) / CLOCKS_PER_SEC * 1000.0;

        cout << "Operation " << (i + 1) << ":" << endl;
        gmp_printf("  %Zd^%Zd mod (64-bit prime) = %Zd\n",
            base[i], exponent[i], result[i]);
        printf("  Time: %.3f ms\n", time_op);
    }
    clock_t total_end = clock();
    double total_time = (static_cast<double>(total_end) - static_cast<double>(total_start)) / CLOCKS_PER_SEC * 1000.0;

    cout << "\nTotal sequential time: " << total_time << " ms" << endl;
    cout << "With perfect parallelization on " << NUM_OPERATIONS
        << " cores: ~" << (total_time / NUM_OPERATIONS) << " ms" << endl;
    cout << "\nNote: Real parallel implementation would use pthread or OpenMP" << endl;
    cout << "Each thread would have its own mpz_t variables to avoid contention." << endl;

    // Cleanup
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        mpz_clear(base[i]);
        mpz_clear(exponent[i]);
        mpz_clear(modulus[i]);
        mpz_clear(result[i]);
    }
}
