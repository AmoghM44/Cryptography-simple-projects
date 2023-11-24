import random
import tkinter as tk

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def find_coprime(phi):
    while True:
        e = random.randrange(2, phi)
        if gcd(e, phi) == 1:
            return e

def find_private_key(e, phi):
    d = 0
    k = 1
    while True:
        d = (phi * k + 1) / e
        if d.is_integer():
            return int(d)
        k += 1

def modular_exp(base, exponent, modulus):
    result = (base**exponent)%modulus
    return result

def rsa_encrypt(plaintext, e, n):
    ciphertext = []
    for symbol in plaintext:
        ciphertext.append(modular_exp(ord(symbol), e, n))
    return ciphertext

def rsa_decrypt(ciphertext, d, n):
    plaintext = []
    for symbol in ciphertext:
        plaintext.append(chr(modular_exp(symbol, d, n)))
    return ''.join(plaintext)

def encrypt_decrypt():
    p = int(p_entry.get())
    q = int(q_entry.get())
    n = p * q
    phi = (p - 1) * (q - 1)
    e = find_coprime(phi)
    d = find_private_key(e, phi)
    plaintext = plaintext_entry.get()
    ciphertext = rsa_encrypt(plaintext, e, n)
    decrypted_message = rsa_decrypt(ciphertext, d, n)
    ciphertext_label.config(text=f'Ciphertext: {ciphertext}')
    decrypted_label.config(text=f'Decrypted message: {decrypted_message}')

# Create the Tkinter window
window = tk.Tk()
window.title("RSA Encryption and Decryption")

# Create input fields and labels
p_label = tk.Label(window, text="Enter the value of p:")
p_label.pack()
p_entry = tk.Entry(window)
p_entry.pack()

q_label = tk.Label(window, text="Enter the value of q:")
q_label.pack()
q_entry = tk.Entry(window)
q_entry.pack()

plaintext_label = tk.Label(window, text="Enter Plaintext:")
plaintext_label.pack()
plaintext_entry = tk.Entry(window)
plaintext_entry.pack()

# Create a button to trigger the encryption and decryption
encrypt_button = tk.Button(window, text="Encrypt/Decrypt", command=encrypt_decrypt)
encrypt_button.pack()

# Create labels for displaying the ciphertext and decrypted message
ciphertext_label = tk.Label(window, text="Ciphertext: ")
ciphertext_label.pack()

decrypted_label = tk.Label(window, text="Decrypted message: ")
decrypted_label.pack()

# Run the Tkinter main loop
window.mainloop()
