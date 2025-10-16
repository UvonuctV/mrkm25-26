/*
 * Лабораторна робота №1 - Crypto++
 * Гібрідна криптосистема RSA + AES
 * Платформа: Windows x64, Visual Studio 2022, C++17
 * Залежності: Crypto++ через vcpkg
 */

#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <windows.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

// Підтримка кирилиці в консолі
void setupConsole() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::cout.imbue(std::locale(""));
}

// Клас для роботи з Crypto++
class CryptoPPHybridCrypto {
private:
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    SecByteBlock aesKey;
    byte aesIV[AES::BLOCKSIZE];

public:
    CryptoPPHybridCrypto() : aesKey(AES::DEFAULT_KEYLENGTH) {}

    // Генерація RSA ключової пари (2048 біт)
    void generateRSAKeypair() {
        privateKey.GenerateRandomWithKeySize(rng, 2048);
        publicKey.AssignFrom(privateKey);
    }

    // Генерація AES-256 ключа та IV
    void generateAESKey() {
        rng.GenerateBlock(aesKey, aesKey.size());
        rng.GenerateBlock(aesIV, AES::BLOCKSIZE);
    }

    // Шифрування даних за допомогою AES-256-CBC
    std::string encryptAES(const std::string& plaintext) {
        std::string ciphertext;

        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(aesKey, aesKey.size(), aesIV);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryption,
                new StringSink(ciphertext)
            )
        );

        return ciphertext;
    }

    // Дешифрування даних за допомогою AES-256-CBC
    std::string decryptAES(const std::string& ciphertext) {
        std::string plaintext;

        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(aesKey, aesKey.size(), aesIV);

        StringSource(ciphertext, true,
            new StreamTransformationFilter(decryption,
                new StringSink(plaintext)
            )
        );

        return plaintext;
    }

    // Шифрування AES ключа за допомогою RSA
    std::string encryptRSA() {
        std::string encryptedKey;

        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

        StringSource(aesKey, aesKey.size(), true,
            new PK_EncryptorFilter(rng, encryptor,
                new StringSink(encryptedKey)
            )
        );

        return encryptedKey;
    }

    // Дешифрування AES ключа за допомогою RSA
    void decryptRSA(const std::string& encryptedKey) {
        std::string decryptedKey;

        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

        StringSource(encryptedKey, true,
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(decryptedKey)
            )
        );

        std::memcpy(aesKey.data(), decryptedKey.data(), aesKey.size());
    }

    size_t getEncryptedKeySize() const {
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        return encryptor.FixedCiphertextLength();
    }
};

// Benchmark функція
void runBenchmark() {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Crypto++ - Тестування гібрідної криптосистеми RSA+AES    ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";

    CryptoPPHybridCrypto crypto;

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
    std::cout << "║                РЕЗУЛЬТАТИ БЕНЧМАРКІНГУ (Crypto++)             ║\n";
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

    std::cout << "🔬 Бібліотека: Crypto++ 8.9+\n";
    std::cout << "💻 Платформа: Windows x64\n";
    std::cout << "🛠️  Компілятор: MSVC (Visual Studio 2022)\n";
    std::cout << "📚 Стандарт: C++17\n\n";
}

int main() {
    setupConsole();

    try {
        runBenchmark();
    }
    catch (const Exception& e) {
        std::cerr << "❌ Crypto++ помилка: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "❌ Помилка: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Натисніть Enter для виходу...";
    std::cin.get();
    return 0;
}