#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Лабораторна робота №1 - PyCryptodome
Гібрідна криптосистема RSA + AES
Платформа: Windows x64, Python 3.13.7
Залежності: PyCryptodome
"""

import time
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class PyCryptodomeHybridCrypto:
    """Клас для роботи з гібрідною криптосистемою"""
    
    def __init__(self):
        self.rsa_key = None
        self.aes_key = None
        self.aes_iv = None
    
    def generate_rsa_keypair(self):
        """Генерація RSA ключової пари (2048 біт)"""
        self.rsa_key = RSA.generate(2048)
    
    def generate_aes_key(self):
        """Генерація AES-256 ключа та IV"""
        self.aes_key = get_random_bytes(32)  # AES-256: 32 байти
        self.aes_iv = get_random_bytes(16)    # AES block size: 16 байт
    
    def encrypt_aes(self, plaintext: str) -> bytes:
        """Шифрування даних за допомогою AES-256-CBC"""
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        plaintext_bytes = plaintext.encode('utf-8')
        padded_plaintext = pad(plaintext_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext
    
    def decrypt_aes(self, ciphertext: bytes) -> str:
        """Дешифрування даних за допомогою AES-256-CBC"""
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        return plaintext.decode('utf-8')
    
    def encrypt_rsa(self) -> bytes:
        """Шифрування AES ключа за допомогою RSA"""
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key.publickey())
        encrypted_key = cipher_rsa.encrypt(self.aes_key)
        return encrypted_key
    
    def decrypt_rsa(self, encrypted_key: bytes):
        """Дешифрування AES ключа за допомогою RSA"""
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
        self.aes_key = cipher_rsa.decrypt(encrypted_key)


def format_time(microseconds: float, unit: str = "мкс") -> str:
    """Форматування часу для виводу"""
    return f"{microseconds:.0f} {unit}"


def run_benchmark():
    """Benchmark функція"""
    print("\n╔════════════════════════════════════════════════════════════════╗")
    print("║   PyCryptodome - Тестування гібрідної криптосистеми RSA+AES  ║")
    print("╚════════════════════════════════════════════════════════════════╝\n")
    
    crypto = PyCryptodomeHybridCrypto()
    
    # Тестові дані
    plaintext = ("Це тестове повідомлення для лабораторної роботи №1. "
                "Гібрідна криптосистема RSA-2048 + AES-256-CBC. "
                "КПІ ім. Ігоря Сікорського, 2025 рік. Підгрупа 2А.")
    
    print(f'📝 Оригінальний текст:\n   "{plaintext}"\n')
    print(f"📊 Розмір даних: {len(plaintext)} байт\n")
    
    # 1. Генерація RSA ключової пари
    start = time.perf_counter()
    crypto.generate_rsa_keypair()
    duration_rsa_gen = (time.perf_counter() - start) * 1000  # мс
    
    print("🔐 КРОК 1: Генерація RSA-2048 ключової пари")
    print(f"   ⏱️  Час: {duration_rsa_gen:.0f} мс")
    print("   ✅ Успішно згенеровано\n")
    
    # 2. Генерація AES ключа
    start = time.perf_counter()
    crypto.generate_aes_key()
    duration_aes_gen = (time.perf_counter() - start) * 1_000_000  # мкс
    
    print("🔑 КРОК 2: Генерація AES-256 ключа та IV")
    print(f"   ⏱️  Час: {duration_aes_gen:.0f} мкс")
    print("   ✅ Успішно згенеровано\n")
    
    # 3. Шифрування даних з AES
    start = time.perf_counter()
    ciphertext = crypto.encrypt_aes(plaintext)
    duration_aes_enc = (time.perf_counter() - start) * 1_000_000  # мкс
    
    print("🔒 КРОК 3: Шифрування даних з AES-256-CBC")
    print(f"   ⏱️  Час: {duration_aes_enc:.0f} мкс")
    print(f"   📦 Розмір шифротексту: {len(ciphertext)} байт")
    print("   ✅ Дані зашифровано\n")
    
    # 4. Шифрування AES ключа з RSA
    start = time.perf_counter()
    encrypted_key = crypto.encrypt_rsa()
    duration_rsa_enc = (time.perf_counter() - start) * 1_000_000  # мкс
    
    print("🔐 КРОК 4: Шифрування AES ключа з RSA-2048")
    print(f"   ⏱️  Час: {duration_rsa_enc:.0f} мкс")
    print(f"   📦 Розмір зашифрованого ключа: {len(encrypted_key)} байт")
    print("   ✅ Ключ зашифровано\n")
    
    print("─────────────────────────────────────────────────────────────────")
    print("           📨 ПЕРЕДАЧА ДАНИХ (ciphertext + encrypted_key)")
    print("─────────────────────────────────────────────────────────────────\n")
    
    # 5. Дешифрування AES ключа з RSA
    start = time.perf_counter()
    crypto.decrypt_rsa(encrypted_key)
    duration_rsa_dec = (time.perf_counter() - start) * 1_000_000  # мкс
    
    print("🔓 КРОК 5: Дешифрування AES ключа з RSA-2048")
    print(f"   ⏱️  Час: {duration_rsa_dec:.0f} мкс")
    print("   ✅ Ключ відновлено\n")
    
    # 6. Дешифрування даних з AES
    start = time.perf_counter()
    decrypted_text = crypto.decrypt_aes(ciphertext)
    duration_aes_dec = (time.perf_counter() - start) * 1_000_000  # мкс
    
    print("🔓 КРОК 6: Дешифрування даних з AES-256-CBC")
    print(f"   ⏱️  Час: {duration_aes_dec:.0f} мкс")
    print("   ✅ Дані дешифровано\n")
    
    # Перевірка коректності
    print(f'🔍 Відновлений текст:\n   "{decrypted_text}"\n')
    
    success = (plaintext == decrypted_text)
    print(f"✅ Верифікація: {'УСПІШНО ✓' if success else 'ПОМИЛКА ✗'}\n")
    
    # Підсумкова таблиця
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║              РЕЗУЛЬТАТИ БЕНЧМАРКІНГУ (PyCryptodome)           ║")
    print("╠════════════════════════════════════════════════════════════════╣")
    print("║ Операція                        │ Час виконання               ║")
    print("╟─────────────────────────────────┼─────────────────────────────╢")
    print(f"║ Генерація RSA-2048              │ {duration_rsa_gen:>20.0f} мс    ║")
    print(f"║ Генерація AES-256               │ {duration_aes_gen:>20.0f} мкс   ║")
    print(f"║ Шифрування AES (даних)          │ {duration_aes_enc:>20.0f} мкс   ║")
    print(f"║ Шифрування RSA (ключа)          │ {duration_rsa_enc:>20.0f} мкс   ║")
    print(f"║ Дешифрування RSA (ключа)        │ {duration_rsa_dec:>20.0f} мкс   ║")
    print(f"║ Дешифрування AES (даних)        │ {duration_aes_dec:>20.0f} мкс   ║")
    print("╟─────────────────────────────────┼─────────────────────────────╢")
    
    total_enc = duration_aes_enc + duration_rsa_enc
    total_dec = duration_aes_dec + duration_rsa_dec
    
    print(f"║ ЗАГАЛЬНИЙ ЧАС ШИФРУВАННЯ        │ {total_enc:>20.0f} мкс   ║")
    print(f"║ ЗАГАЛЬНИЙ ЧАС ДЕШИФРУВАННЯ      │ {total_dec:>20.0f} мкс   ║")
    print("╚════════════════════════════════════════════════════════════════╝\n")
    
    # Продуктивність
    throughput_enc = (len(plaintext) / 1024.0) / (total_enc / 1_000_000.0)
    throughput_dec = (len(plaintext) / 1024.0) / (total_dec / 1_000_000.0)
    
    print("📊 ПРОДУКТИВНІСТЬ:")
    print(f"   Шифрування: {throughput_enc:.2f} KB/s")
    print(f"   Дешифрування: {throughput_dec:.2f} KB/s\n")
    
    print(f"🔬 Бібліотека: PyCryptodome {get_pycryptodome_version()}")
    print("💻 Платформа: Windows x64")
    print(f"🐍 Python: {sys.version.split()[0]}")
    print("📚 Алгоритми: RSA-2048 + AES-256-CBC\n")


def get_pycryptodome_version():
    """Отримання версії PyCryptodome"""
    try:
        from Crypto import __version__
        return __version__
    except:
        return "3.x"


if __name__ == "__main__":
    try:
        run_benchmark()
    except Exception as e:
        print(f"❌ Помилка: {e}", file=sys.stderr)
        sys.exit(1)
    
    input("Натисніть Enter для виходу...")
