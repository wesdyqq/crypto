try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.Util.Padding import pad, unpad
    from Cryptodome.Random import get_random_bytes
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
import os
import sys
import base64
import hashlib
def clear_screen():
    """Очищает экран консоли"""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_header():
    """Выводит ASCII-арт заголовка"""
    header = r"""
    █     █░▓█████   ██████ ▓█████▄▓██   ██▓
    ▓█░ █ ░█░▓█   ▀ ▒██    ▒ ▒██▀ ██▌▒██  ██▒
    ▒█░ █ ░█ ▒███   ░ ▓██▄   ░██   █▌ ▒██ ██░
    ░█░ █ ░█ ▒▓█  ▄   ▒   ██▒░▓█▄   ▌ ░ ▐██▓░
    ░░██▒██▓ ░▒████▒▒██████▒▒░▒████▓  ░ ██▒▓░
    ░ ▓░▒ ▒  ░░ ▒░ ░▒ ▒▓▒ ▒ ░ ▒▒▓  ▒   ██▒▒▒ 
      ▒ ░ ░   ░ ░  ░░ ░▒  ░ ░ ░ ▒  ▒ ▓██ ░▒░ 
      ░   ░     ░   ░  ░  ░   ░ ░  ░ ▒ ▒ ░░  
        ░       ░  ░      ░     ░    ░ ░     
                              ░      ░ ░     
    """
    print("\033[36m" + header + "\033[0m")  # Голубой цвет
    print("{:^80}".format("🔒 ШИФРАТОР 3000 | AES-256-CBC 🔓"))
    print("-" * 80)

def get_key(password: str, salt: bytes) -> bytes:
    """Генерирует ключ 32 байта (AES-256) из пароля и соли"""
    return PBKDF2(password.encode(), salt, dkLen=32, count=1000000, 
                 prf=lambda p, s: hashlib.sha256(p + s).digest())

def encrypt(plaintext: str, password: str) -> str:
    """Шифрует текст и возвращает строку в формате 'salt:iv:ciphertext'"""
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    key = get_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return f"{base64.b64encode(salt).decode()}:{base64.b64encode(iv).decode()}:{base64.b64encode(ciphertext).decode()}"

def decrypt(encrypted: str, password: str) -> str:
    """Дешифрует строку формата 'salt:iv:ciphertext'"""
    try:
        salt_b64, iv_b64, ciphertext_b64 = encrypted.split(":")
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        key = get_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()
    except Exception as e:
        return f"Ошибка: {str(e)}"

def main():
    while True:
        clear_screen()
        show_header()
        
        print("\n{:<20} {:<50}".format("1️⃣", "Зашифровать текст"))
        print("{:<20} {:<50}".format("2️⃣", "Дешифровать текст"))
        print("{:<20} {:<50}".format("0️⃣", "Выход"))
        
        choice = input("\n>>> Выберите действие (1/2/0): ")
        
        if choice == "1":
            clear_screen()
            show_header()
            print("\n🔐 ШИФРОВАНИЕ")
            print("-" * 60)
            text = input("Введите текст: ")
            password = input("Введите пароль: ")
            encrypted = encrypt(text, password)
            print("\n" + "=" * 60)
            print("✅ Успешно зашифровано!\n")
            print("🔑 Результат (сохраните это):")
            print("\033[33m" + encrypted + "\033[0m")  # Желтый цвет
            input("\nНажмите Enter чтобы продолжить...")
            
        elif choice == "2":
            clear_screen()
            show_header()
            print("\n🔓 ДЕШИФРОВАНИЕ")
            print("-" * 60)
            encrypted = input("Введите зашифрованный текст (salt:iv:ciphertext): ")
            password = input("Введите пароль: ")
            decrypted = decrypt(encrypted, password)
            print("\n" + "=" * 60)
            if decrypted.startswith("Ошибка"):
                print("\033[31m" + decrypted + "\033[0m")  # Красный для ошибок
            else:
                print("✅ Успешно расшифровано!\n")
                print("📜 Исходный текст:")
                print("\033[32m" + decrypted + "\033[0m")  # Зеленый цвет
            input("\nНажмите Enter чтобы продолжить...")
            
        elif choice == "0":
            clear_screen()
            print("\n" + "=" * 60)
            print("{:^60}".format("🚪 Выход из программы..."))
            print("{:^60}".format("До свидания!"))
            print("=" * 60 + "\n")
            break
            
        else:
            print("\033[31m\n⚠ Неверный выбор!\033[0m")
            input("Нажмите Enter чтобы продолжить...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем")
        sys.exit(0)