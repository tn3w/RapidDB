import os
import json
import secrets
from threading import Lock
from base64 import urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Union, Optional

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
