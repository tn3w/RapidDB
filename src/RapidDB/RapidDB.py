import os
import json
import secrets
from threading import Lock
from base64 import b64encode, b64decode, urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Union, Optional, Tuple

file_locks = dict()

class JSON:

    def load(file_name: str) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        """

        if not os.path.isfile(file_name):
            raise FileNotFoundError("File '" + file_name + "' does not exist.")
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "r") as file:
                data = json.load(file)
            return data
        
    def dump(data: Union[dict, list], file_name: str) -> None:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_name: The file to save to
        """

        file_directory = os.path.dirname(file_name)
        if not os.path.isdir(file_directory):
            raise FileNotFoundError("Directory '" + file_directory + "' does not exist.")
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "w") as file:
                json.dump(data, file)

class Hashing:
    """
    Implementation of hashing with SHA256 and 100000 iterations
    """

    def __init__(self, salt: Optional[str] = None):
        """
        :param salt: The salt, makes the hashing process more secure
        """

        self.salt = salt

    def hash(self, plain_text: str, hash_length: int = 32) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        plain_text = str(plain_text).encode('utf-8')

        salt = self.salt
        if salt is None:
            salt = secrets.token_bytes(32)
        else:
            if not isinstance(salt, bytes):
                try:
                    salt = bytes.fromhex(salt)
                except:
                    salt = salt.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=hash_length,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        hashed_data = kdf.derive(plain_text)

        hash = urlsafe_b64encode(hashed_data).decode('utf-8') + "//" + salt.hex()
        return hash

    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """

        salt = self.salt
        if "//" in hash:
            hash, salt = hash.split("//")

        if salt is None:
            raise ValueError("Salt cannot be None if there is no salt in hash")
        
        salt = bytes.fromhex(salt)

        hash_length = len(urlsafe_b64decode(hash.encode('utf-8')))

        comparison_hash = Hashing(salt=salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash

class NoEncryption:
    """
    A class that does virtually nothing
    """

    def __init__(self):
        pass

    @property
    def use_hashing():
        return False
    
    def encrypt(self: Optional["NoEncryption"] = None, plain_text: str = None) -> str:
        return plain_text
    
    def decrypt(self: Optional["NoEncryption"] = None, cipher_chat: str = None) -> str:
        return cipher_chat

class SymmetricEncryption:
    """
    Implementation of symmetric encryption with AES
    """

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 16 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        if password is None:
            password = secrets.token_urlsafe(64)

        self.password = password.encode()
        self.salt_length = salt_length

    @property
    def use_hashing():
        return True

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = urlsafe_b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()

class AsymmetricEncryption:
    """
    Implementation of secure asymmetric encryption with RSA
    """

    def __init__(self, public_key: Optional[str] = None, private_key: Optional[str] = None):
        """
        :param public_key: The public key to encrypt a message / to verify a signature
        :param private_key: The private key to decrypt a message / to create a signature
        """
        
        self.public_key, self.private_key = public_key, private_key

        if not public_key is None:
            self.publ_key = serialization.load_der_public_key(b64decode(public_key), backend=default_backend())
        else:
            self.publ_key = None

        if not private_key is None:
            self.priv_key = serialization.load_der_private_key(b64decode(private_key), password=None, backend=default_backend())
        else:
            self.priv_key = None

    @property
    def use_hashing():
        return True

    def generate_keys(self, key_size: int = 2048) -> "AsymmetricEncryption":
        """
        Generates private and public key

        :param key_size: The key size of the private key
        """
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.private_key = b64encode(self.priv_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )).decode('utf-8')
        
        self.publ_key = self.priv_key.public_key()
        self.public_key = b64encode(self.publ_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')

        return self
    
    def encrypt(self, plain_text: str) -> Tuple[str, str]:
        """
        Encrypt the provided plain_text using asymmetric and symmetric encryption

        :param plain_text: The text to be encrypted
        """

        if self.publ_key is None:
            raise ValueError("The public key cannot be None in encode, this error occurs because no public key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        symmetric_key = secrets.token_bytes(128)

        cipher_text = SymmetricEncryption(symmetric_key).encrypt(plain_text)

        encrypted_symmetric_key = self.publ_key.encrypt(
            symmetric_key,
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm = hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        # Combine and encode the encrypted key and the encrypted text
        encrypted_key = b64encode(encrypted_symmetric_key).decode('utf-8')
        return f"{encrypted_key}//{cipher_text}"

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypt the provided cipher_text using asymmetric and symmetric decryption

        :param cipher_text: The encrypted message with the encrypted symmetric key
        """

        if self.priv_key is None:
            raise ValueError("The private key cannot be None in decode, this error occurs because no private key was specified when initializing the AsymmetricCrypto function and none was generated with generate_keys.")

        encrypted_key, cipher_text = cipher_text.split("//")[0], cipher_text.split("//")[1]
        encrypted_symmetric_key = b64decode(encrypted_key.encode('utf-8'))

        symmetric_key = self.priv_key.decrypt(
            encrypted_symmetric_key, 
            asy_padding.OAEP(
                mgf = asy_padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        plain_text = SymmetricEncryption(symmetric_key).decrypt(cipher_text)

        return plain_text
