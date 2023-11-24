import numpy as np
import sympy
import string
import random

# Define variables
dimension = int(input("Enter size of key matrix: ")) # Your N
key_matrix = np.zeros((dimension,dimension), dtype=int)
for i in range(dimension):
    key_matrix[i] = list(map(int, input().split(" ")))
key = np.matrix(key_matrix) # Your key
message = input("Enter message to encrypt: ")# Your message

print("Plain Text: "+message)
print("Key Matrix: ")
print(key)
# Generate the alphabet
alphabet = string.ascii_lowercase

# Encrypted message
encryptedMessage = ""

# Group message in vectors and generate crypted message
for index, i in enumerate(message): #PAYMOREMONEY 
    values = []
    # Make bloc of N values
    if index % dimension == 0:
        for j in range(0, dimension):
            if(index + j < len(message)):
                values.append([alphabet.index(message[index + j])])
                # print(f'if:{values}')
            else:
                values.append([random.randint(0,25)])
                # print(f'else:{values}')
        # Generate vectors and work with them
        vector = np.matrix(values)
        vector = key * vector
        vector %= 26
        for j in range(0, dimension):
            encryptedMessage += alphabet[vector.item(j)]

# Show the result
print("Encrypted message is: "+ encryptedMessage.upper())

#DECRYPTION

def modulo_multiplicative_inverse(A, M):

    # This will iterate from 0 to M-1
    for i in range(0, M):
        # If we have our multiplicative inverse then return it
        if (A*i) % M == 1:
            return i
    # If we didn't find the multiplicative inverse in the loop above
    # then it doesn't exist for A under M
    return -1


matrix= sympy.Matrix(key_matrix)
adj=(matrix.adjugate()%26) #TO FIND ADJOINT OF KEY MATRIX

mat=np.matrix(key_matrix)

det=(round(np.linalg.det(mat))%26) #TO FIND DETERMINENT

# print(det)
# print(adj)

mult_inverse=modulo_multiplicative_inverse(det, 26)

# print(mult_inverse)

inv_m=(mult_inverse*adj)%26
print("inverse of Key Matrix: ")
print(inv_m)

decryptedMessage=""

for index, i in enumerate(encryptedMessage): 
    values = []
    if index % dimension == 0:
        for j in range(0, dimension):
            if(index + j < len(encryptedMessage)):
                values.append([alphabet.index(encryptedMessage[index + j])])
            else:
                values.append([random.randint(0,25)])
        vector = np.matrix(values)
        vector = inv_m * vector
        vector %= 26
        for j in range(0, dimension):
            decryptedMessage += alphabet[vector[j]]

# Show the result
print("Decrypted Message: "+ decryptedMessage)
