import base64
from pwinput import pwinput
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def generate_key(password):
    salt = b'<salt aqui'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_message(message, password):
    key = generate_key(password)
    encoded_message = message.encode()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(encoded_message)
    return encrypted_message

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message)
    return decrypted_message.decode()

def write_to_file(file_path, encrypted_message):
    with open(file_path, "wb") as file:
        file.write(encrypted_message)

def read_from_file(file_path):
    with open(file_path, "rb") as file:
        encrypted_message = file.read()
    return encrypted_message

# exemplo de uso
password = b'<secret aqui>'
message = pwinput(prompt='insira a senha a ser criptografada: ', mask='*')
file_path = 'overdue1.dll'

encrypted_message = encrypt_message(message, password)
write_to_file(file_path, encrypted_message)

encrypted_message = read_from_file(file_path)
decrypted_message = decrypt_message(encrypted_message, password)

print('Mensagem original:', message)
print('Mensagem criptografada:', encrypted_message)
print('Mensagem descriptografada:', decrypted_message)
