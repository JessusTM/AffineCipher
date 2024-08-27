import math


def gcd(a, b):
    return math.gcd(a, b)


def modularInverse(a, m):
    originalModulus = m
    x, y = 0, 1

    while m > 0:
        quotient = a // m
        a, m = m, a % m
        x, y = y, x - quotient * y

    if x < 0:
        x += originalModulus

    return x


def affineCaesarEncryption(message, key, alphabet):
    alphabetSize = len(alphabet)
    multiplicativeKey, additiveKey = key

    if gcd(multiplicativeKey, alphabetSize) != 1:
        return "MultiplicativeKey and alphabetSize are not coprime"

    encryptedMessage = ""

    for character in message:
        if character in alphabet:
            originalIndex = alphabet.index(character)
            encryptedIndex = (
                multiplicativeKey * originalIndex + additiveKey
            ) % alphabetSize
            encryptedMessage += alphabet[encryptedIndex]
        else:
            encryptedMessage += character

    return encryptedMessage


def affineCaesarDecryption(ciphertext, key, alphabet):
    alphabetSize = len(alphabet)
    multiplicativeKey, additiveKey = key

    if gcd(multiplicativeKey, alphabetSize) != 1:
        return "MultiplicativeKey and alphabetSize are not coprime"

    decryptedMessage = ""
    multiplicativeInverse = modularInverse(multiplicativeKey, alphabetSize)

    for character in ciphertext:
        if character in alphabet:
            encryptedIndex = alphabet.index(character)
            decryptedIndex = (
                multiplicativeInverse * (encryptedIndex - additiveKey)
            ) % alphabetSize
            decryptedMessage += alphabet[decryptedIndex]
        else:
            decryptedMessage += character

    return decryptedMessage


def menu():
    while True:
        print("         ----- Affine Caesar Cipher ----- ")
        print("             [1] Encode")
        print("             [2] Decode")
        print("             [3] Exit")
        print("         ------------------------- ")
        option = int(input("            Option: "))
        print("         ------------------------- ")

        if option == 1:
            print("         --------- Encode -------- ")
            message = input("          Message              : ")
            alphabet = input("          Alphabet             : ")
            multiplicativeKey = int(input("          Multiplicative Key   : "))
            additiveKey = int(input("          Additive Key         : "))

            key = (multiplicativeKey, additiveKey)
            encryptedMessage = affineCaesarEncryption(message, key, alphabet)

            print(f"""
                         ---------------------------------------------------------------
                                                Encode Results
                         ---------------------------------------------------------------
                                Message              : {message}
                                Alphabet             : {alphabet}
                                Multiplicative Key   : {multiplicativeKey}
                                Additive Key         : {additiveKey}
                                Encrypted Message    : {encryptedMessage}
                         ---------------------------------------------------------------
                      """)

        elif option == 2:
            print("         --------- Decode -------- ")
            ciphertext = input("          Ciphertext           : ")
            alphabet = input("          Alphabet             : ")
            multiplicativeKey = int(input("          Multiplicative Key   : "))
            additiveKey = int(input("          Additive Key         : "))

            key = (multiplicativeKey, additiveKey)
            decrypted_message = affineCaesarDecryption(ciphertext, key, alphabet)

            print(f"""
                         ---------------------------------------------------------------
                                                Decode Results
                         ---------------------------------------------------------------
                                Ciphertext           : {ciphertext}
                                Alphabet             : {alphabet}
                                Multiplicative Key   : {multiplicativeKey}
                                Additive Key         : {additiveKey}
                                Decrypted Message    : {decrypted_message}
                         ---------------------------------------------------------------
                      """)

        elif option == 3:
            print("     Later...")
            break

        else:
            print("     Invalid option...")


menu()

