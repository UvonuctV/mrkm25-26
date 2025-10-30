/*
 * Лабораторна робота №1 - OpenSSL
 * Гібрідна криптосистема RSA + AES
 * Платформа: Windows x64, Visual Studio 2022, C++17
 * Залежності: OpenSSL через vcpkg
 */

#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

 // Підтримка кирилиці в консолі
void setupConsole() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::cout.imbue(std::locale(""));
}

// Клас для роботи з OpenSSL
class OpenSSLHybridCrypto {
private:
    EVP_PKEY* rsa_keypair;
    std::vector<unsigned char> aes_key;
    std::vector<unsigned char> aes_iv;

    void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }

public:
    OpenSSLHybridCrypto() : rsa_keypair(nullptr) {
        // Ініціалізація OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    ~OpenSSLHybridCrypto() {
        if (rsa_keypair) {
            EVP_PKEY_free(rsa_keypair);
        }
        EVP_cleanup();
        ERR_free_strings();
    }

    // Генерація RSA ключової пари (2048 біт)
    void generateRSAKeypair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) handleErrors();

        if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleErrors();

        if (EVP_PKEY_keygen(ctx, &rsa_keypair) <= 0) handleErrors();

        EVP_PKEY_CTX_free(ctx);
    }

    // Генерація AES-256 ключа та IV
    void generateAESKey() {
        aes_key.resize(32);  // AES-256: 32 байти
        aes_iv.resize(16);   // AES block size: 16 байт

        if (RAND_bytes(aes_key.data(), 32) != 1) handleErrors();
        if (RAND_bytes(aes_iv.data(), 16) != 1) handleErrors();
    }

    // Шифрування даних за допомогою AES-256-CBC
    std::vector<unsigned char> encryptAES(const std::string& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
            aes_key.data(), aes_iv.data()) != 1) {
            handleErrors();
        }

        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
            (unsigned char*)plaintext.c_str(),
            plaintext.size()) != 1) {
            handleErrors();
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            handleErrors();
        }
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    // Дешифрування даних за допомогою AES-256-CBC
    std::string decryptAES(const std::vector<unsigned char>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) handleErrors();

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
            aes_key.data(), aes_iv.data()) != 1) {
            handleErrors();
        }

        std::vector<unsigned char> plaintext(ciphertext.size());
        int len = 0, plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
            ciphertext.data(), ciphertext.size()) != 1) {
            handleErrors();
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            handleErrors();
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
    }

    // Шифрування AES ключа за допомогою RSA
    std::vector<unsigned char> encryptRSA() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
        if (!ctx) handleErrors();

        if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            handleErrors();
        }

        size_t outlen;
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, aes_key.data(), 32) <= 0) {
            handleErrors();
        }

        std::vector<unsigned char> encrypted_key(outlen);
        if (EVP_PKEY_encrypt(ctx, encrypted_key.data(), &outlen,
            aes_key.data(), 32) <= 0) {
            handleErrors();
        }

        EVP_PKEY_CTX_free(ctx);
        return encrypted_key;
    }

    // Дешифрування AES ключа за допомогою RSA
    void decryptRSA(const std::vector<unsigned char>& encrypted_key) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
        if (!ctx) handleErrors();

        if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            handleErrors();
        }

        size_t outlen;
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen,
            encrypted_key.data(), encrypted_key.size()) <= 0) {
            handleErrors();
        }

        std::vector<unsigned char> decrypted_key(outlen);
        if (EVP_PKEY_decrypt(ctx, decrypted_key.data(), &outlen,
            encrypted_key.data(), encrypted_key.size()) <= 0) {
            handleErrors();
        }

        aes_key = decrypted_key;
        EVP_PKEY_CTX_free(ctx);
    }
};

// Benchmark функція
void runBenchmark() {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     OpenSSL - Тестування гібрідної криптосистеми RSA+AES     ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";

    OpenSSLHybridCrypto crypto;

    // Тестові дані
    std::string plaintext = "Це тестове повідомлення для лабораторної роботи №1. "
        "Гібрідна криптосистема RSA-2048 + AES-256-CBC. "
        "КПІ ім. Ігоря Сікорського, 2025 рік. Підгрупа 2А.";

    std::cout << "📝 Оригінальний текст:\n   \"" << plaintext << "\"\n\n";
    std::cout << "📊 Розмір даних: " << plaintext.size() << " байт\n\n";

    // 1. Генерація RSA ключової пари
    auto start = std::chrono::high_resolution_clock::now();
    crypto.generateRSAKeypair();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration_rsa_gen = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "🔐 КРОК 1: Генерація RSA-2048 ключової пари\n";
    std::cout << "   ⏱️  Час: " << duration_rsa_gen.count() << " мс\n";
    std::cout << "   ✅ Успішно згенеровано\n\n";

    // 2. Генерація AES ключа
    start = std::chrono::high_resolution_clock::now();
    crypto.generateAESKey();
    end = std::chrono::high_resolution_clock::now();
    auto duration_aes_gen = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "🔑 КРОК 2: Генерація AES-256 ключа та IV\n";
    std::cout << "   ⏱️  Час: " << duration_aes_gen.count() << " мкс\n";
    std::cout << "   ✅ Успішно згенеровано\n\n";

    // 3. Шифрування даних з AES
    start = std::chrono::high_resolution_clock::now();
    auto ciphertext = crypto.encryptAES(plaintext);
    end = std::chrono::high_resolution_clock::now();
    auto duration_aes_enc = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "🔒 КРОК 3: Шифрування даних з AES-256-CBC\n";
    std::cout << "   ⏱️  Час: " << duration_aes_enc.count() << " мкс\n";
    std::cout << "   📦 Розмір шифротексту: " << ciphertext.size() << " байт\n";
    std::cout << "   ✅ Дані зашифровано\n\n";

    // 4. Шифрування AES ключа з RSA
    start = std::chrono::high_resolution_clock::now();
    auto encrypted_key = crypto.encryptRSA();
    end = std::chrono::high_resolution_clock::now();
    auto duration_rsa_enc = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "🔐 КРОК 4: Шифрування AES ключа з RSA-2048\n";
    std::cout << "   ⏱️  Час: " << duration_rsa_enc.count() << " мкс\n";
    std::cout << "   📦 Розмір зашифрованого ключа: " << encrypted_key.size() << " байт\n";
    std::cout << "   ✅ Ключ зашифровано\n\n";

    std::cout << "─────────────────────────────────────────────────────────────────\n";
    std::cout << "           📨 ПЕРЕДАЧА ДАНИХ (ciphertext + encrypted_key)\n";
    std::cout << "─────────────────────────────────────────────────────────────────\n\n";

    // 5. Дешифрування AES ключа з RSA
    start = std::chrono::high_resolution_clock::now();
    crypto.decryptRSA(encrypted_key);
    end = std::chrono::high_resolution_clock::now();
    auto duration_rsa_dec = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "🔓 КРОК 5: Дешифрування AES ключа з RSA-2048\n";
    std::cout << "   ⏱️  Час: " << duration_rsa_dec.count() << " мкс\n";
    std::cout << "   ✅ Ключ відновлено\n\n";

    // 6. Дешифрування даних з AES
    start = std::chrono::high_resolution_clock::now();
    auto decrypted_text = crypto.decryptAES(ciphertext);
    end = std::chrono::high_resolution_clock::now();
    auto duration_aes_dec = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    std::cout << "🔓 КРОК 6: Дешифрування даних з AES-256-CBC\n";
    std::cout << "   ⏱️  Час: " << duration_aes_dec.count() << " мкс\n";
    std::cout << "   ✅ Дані дешифровано\n\n";

    // Перевірка коректності
    std::cout << "🔍 Відновлений текст:\n   \"" << decrypted_text << "\"\n\n";

    bool success = (plaintext == decrypted_text);
    std::cout << "✅ Верифікація: " << (success ? "УСПІШНО ✓" : "ПОМИЛКА ✗") << "\n\n";

    // Підсумкова таблиця
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                  РЕЗУЛЬТАТИ БЕНЧМАРКІНГУ (OpenSSL)            ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Операція                        │ Час виконання               ║\n";
    std::cout << "╟─────────────────────────────────┼─────────────────────────────╢\n";
    std::cout << "║ Генерація RSA-2048              │ " << std::setw(20) << duration_rsa_gen.count() << " мс    ║\n";
    std::cout << "║ Генерація AES-256               │ " << std::setw(20) << duration_aes_gen.count() << " мкс   ║\n";
    std::cout << "║ Шифрування AES (даних)          │ " << std::setw(20) << duration_aes_enc.count() << " мкс   ║\n";
    std::cout << "║ Шифрування RSA (ключа)          │ " << std::setw(20) << duration_rsa_enc.count() << " мкс   ║\n";
    std::cout << "║ Дешифрування RSA (ключа)        │ " << std::setw(20) << duration_rsa_dec.count() << " мкс   ║\n";
    std::cout << "║ Дешифрування AES (даних)        │ " << std::setw(20) << duration_aes_dec.count() << " мкс   ║\n";
    std::cout << "╟─────────────────────────────────┼─────────────────────────────╢\n";

    auto total_enc = duration_aes_enc.count() + duration_rsa_enc.count();
    auto total_dec = duration_aes_dec.count() + duration_rsa_dec.count();

    std::cout << "║ ЗАГАЛЬНИЙ ЧАС ШИФРУВАННЯ        │ " << std::setw(20) << total_enc << " мкс   ║\n";
    std::cout << "║ ЗАГАЛЬНИЙ ЧАС ДЕШИФРУВАННЯ      │ " << std::setw(20) << total_dec << " мкс   ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";

    // Продуктивність
    double throughput_enc = (plaintext.size() / 1024.0) / (total_enc / 1000000.0);
    double throughput_dec = (plaintext.size() / 1024.0) / (total_dec / 1000000.0);

    std::cout << "📊 ПРОДУКТИВНІСТЬ:\n";
    std::cout << "   Шифрування: " << std::fixed << std::setprecision(2) << throughput_enc << " KB/s\n";
    std::cout << "   Дешифрування: " << throughput_dec << " KB/s\n\n";

    std::cout << "🔬 Бібліотека: OpenSSL 3.x\n";
    std::cout << "💻 Платформа: Windows x64\n";
    std::cout << "🛠️  Компілятор: MSVC (Visual Studio 2022)\n";
    std::cout << "📚 Стандарт: C++17\n\n";
}

int main() {
    setupConsole();

    try {
        runBenchmark();
    }
    catch (const std::exception& e) {
        std::cerr << "❌ Помилка: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Натисніть Enter для виходу...";
    std::cin.get();
    return 0;
}
