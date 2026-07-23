from crypto.aes import AESCipher


def main():
    # Create AES object
    aes = AESCipher()

    # Original message
    message = "Hello Vignesh! Welcome to AES-256 Encryption."

    print("=" * 50)
    print("Original Message:")
    print(message)

    # Encrypt
    encrypted = aes.encrypt(message)

    print("\nEncrypted Message:")
    print(encrypted)

    # Decrypt
    decrypted = aes.decrypt(encrypted)

    print("\nDecrypted Message:")
    print(decrypted)

    print("=" * 50)

    # Verify
    if message == decrypted:
        print("\n✅ Encryption and Decryption Successful!")
    else:
        print("\n❌ Something went wrong!")


if __name__ == "__main__":
    main()