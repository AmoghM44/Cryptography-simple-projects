import random

def generate_key(message):
    key = ""
    for _ in range(len(message)):
        key += chr(random.randint(65, 90))  # Generating a random uppercase letter
    return key

def encrypt(message, key):
    ciphertext = ""
    for i in range(len(message)):
        char = message[i]
        if char.isalpha():
            char = chr((ord(char.upper()) + ord(key[i].upper()) - 2 * ord('A')) % 26 + ord('A'))
        ciphertext += char
    return ciphertext

def decrypt(ciphertext, key):
    message = ""
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        if char.isalpha():
            char = chr((ord(char.upper()) - ord(key[i].upper()) + 26) % 26 + ord('A'))
        message += char
    return message

# Taking user input
msg = input("Enter the message to encrypt: ")

# Generating the key
key = generate_key(msg)
print("Generated Key:", key)

# Encrypting the message
ciphertext = encrypt(msg, key)
print("Ciphertext:", ciphertext)

# Taking user input for decryption
key_input = input("Enter the key: ")
ciphertext_input = input("Enter the ciphertext: ")

# Decrypting the message
decrypted_message = decrypt(ciphertext_input, key_input)
print("Decrypted message:", decrypted_message)

if (decrypted_message != msg.upper()):
    print("The entered ciphertext or key is wrong!!")
else:
    print("Correct!!")
