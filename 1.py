import tkinter as tk
from tkinter import ttk


def affineCipherEncryption(message, key, alphabet):
    alphabetSize = len(alphabet)
    multiplicativeKey, additiveKey = key

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


def modularInverse(alphabetSize, module):
    for x in range(1, module):
        if (alphabetSize * x) % module == 1:
            return x
    return -1


def affineCipherDecryption(ciphertext, key, alphabet):
    alphabetSize = len(alphabet)
    multiplicativeKey, additiveKey = key

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
        print("         ----- Affine Cipher ----- ")
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
            encryptedMessage = affineCipherEncryption(message, key, alphabet)

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
            decrypted_message = affineCipherDecryption(ciphertext, key, alphabet)

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
