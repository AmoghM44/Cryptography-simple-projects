import random
import tkinter as tk

def generate_key(message):
    key = ""
    for _ in range(len(message)):
        key += chr(random.randint(65, 90))
    return key

def encrypt(message, key):
    ciphertext = ""
    for i in range(len(message)):
        if message[i].isalpha():
            char = chr((ord(message[i].upper()) + ord(key[i].upper()) - 2 * ord('A')) % 26 + ord('A'))
            ciphertext += char
        else:
            ciphertext += message[i]
    return ciphertext

def decrypt(ciphertext, key):
    decrypted_message = ""
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            char = chr((ord(ciphertext[i].upper()) - ord(key[i].upper()) + 26) % 26 + ord('A'))
            decrypted_message += char
        else:
            decrypted_message += ciphertext[i]
    return decrypted_message

def encrypt_message():
    message = message_entry.get()
    key = generate_key(message)
    ciphertext = encrypt(message, key)
    key_output.delete(1.0, tk.END)
    key_output.insert(tk.END, key)
    ciphertext_output.delete(1.0, tk.END)
    ciphertext_output.insert(tk.END, ciphertext)

def decrypt_message():
    ciphertext = ciphertext_entry.get(1.0, tk.END).strip()
    key = key_entry.get(1.0, tk.END).strip()
    decrypted_message = decrypt(ciphertext, key)
    decrypted_message_output.delete(1.0, tk.END)
    decrypted_message_output.insert(tk.END, decrypted_message)
    
    original_message = message_entry.get()
    if decrypted_message == original_message.upper():
        result_output.config(text="Correct")
    else:
        result_output.config(text="Wrong")

# Create the main window
window = tk.Tk()
window.title("One-Time Pad Encryption")

# Create the message input and encryption button
message_label = tk.Label(window, text="Enter the message to encrypt:")
message_label.grid(row=0, column=0, padx=10, pady=10)
message_entry = tk.Entry(window, width=50)
message_entry.grid(row=0, column=1, padx=10, pady=10)

encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_message)
encrypt_button.grid(row=0, column=2, padx=10, pady=10)

# Create the labels and output boxes for key and ciphertext
key_label = tk.Label(window, text="Generated Key:")
key_label.grid(row=1, column=0, padx=10, pady=10)
key_output = tk.Text(window, width=50, height=1)
key_output.grid(row=1, column=1, padx=10, pady=10)

ciphertext_label = tk.Label(window, text="Ciphertext:")
ciphertext_label.grid(row=2, column=0, padx=10, pady=10)
ciphertext_output = tk.Text(window, width=50, height=1)
ciphertext_output.grid(row=2, column=1, padx=10, pady=10)

# Create the input boxes and decryption button for ciphertext and key
ciphertext_label = tk.Label(window, text="Enter the ciphertext:")
ciphertext_label.grid(row=4, column=0, padx=10, pady=10)
ciphertext_entry = tk.Text(window, width=50, height=1)
ciphertext_entry.grid(row=4, column=1, padx=10, pady=10)

key_label = tk.Label(window, text="Enter the key:")
key_label.grid(row=3, column=0, padx=10, pady=10)
key_entry = tk.Text(window, width=50, height=1)
key_entry.grid(row=3, column=1, padx=10, pady=10)

decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_message)
decrypt_button.grid(row=4, column=2, padx=10, pady=10)

# Create the output box for decrypted message
decrypted_message_label = tk.Label(window, text="Decrypted Message:")
decrypted_message_label.grid(row=5, column=0, padx=10, pady=10)
decrypted_message_output = tk.Text(window, width=50, height=1)
decrypted_message_output.grid(row=5, column=1, padx=10, pady=10)

# Create the output box for decryption result
result_label = tk.Label(window, text="Decryption Result:")
result_label.grid(row=6, column=0, padx=10, pady=10)
result_output = tk.Label(window, text="")
result_output.grid(row=6, column=1, padx=10, pady=10)

# Start the Tkinter event loop
window.mainloop()
