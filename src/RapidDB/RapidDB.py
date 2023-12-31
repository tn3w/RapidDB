import os
import json
import random
import secrets
import requests
import pkg_resources
from urllib.parse import quote
from flask import Flask, request
from threading import Lock, Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode, urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from typing import Union, Optional, Tuple, Final

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
    def use_hashing(self = None):
        return False
    
    def encrypt(self: Optional["NoEncryption"] = None, plain_text: str = None) -> str:
        return plain_text
    
    def decrypt(self: Optional["NoEncryption"] = None, cipher_text: str = None) -> str:
        return cipher_text

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
        
        if isinstance(password, str):
            password = password.encode()

        self.password = password
        self.salt_length = salt_length

    @property
    def use_hashing(self = None):
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
    def use_hashing(self = None):
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

CURRENT_DIR: Final[str] = pkg_resources.resource_filename("RapidDB", "")
TABLES_DIR: Final[str] = os.path.join(CURRENT_DIR, "tables")
RANDOM_VERBS: Final[list] = ["explore", "discover", "decorate", "whisper", "navigate", "calculate", "promote", "activate", "celebrate", "entertain", "harvest", "invent", "evaluate", "illuminate", "participate", "introduce", "persuade", "generate", "negotiate", "appreciate", "complement", "enthusiasm", "investigate", "encourage", "volunteer", "photograph", "celebration", "accompany", "experience", "understand", "accomplish", "demonstrate", "celebrity", "experience", "strengthen", "criticize", "communicate", "contribute", "distinguish", "elaborate", "illustrate", "manipulate", "acknowledge", "accelerate", "celebratory", "determination", "negotiation"]
RANDOM_NOUNS: Final[list] = ["banana", "elephant", "octopus", "giraffe", "sunshine", "computer", "keyboard", "waterfall", "cucumber", "butterfly", "umbrella", "cooker", "mountain", "firework", "sandwich", "backpack", "calendar", "laughter", "pineapple", "scissors", "sweater", "happiness", "telescope", "notebook", "telephone", "suitcase", "chocolate", "elephant", "sunflower", "sunrise", "helicopter", "treasure", "alligator", "volcano", "whale", "elephant", "tiger", "ocean", "zebra", "dolphin", "moonlight", "hamburger", "sunscreen", "umbrella", "rainbow", "guitar", "keyboard"]

if not os.path.isdir(TABLES_DIR):
    os.mkdir(TABLES_DIR)

class DB(dict):

    def __init__(self, table_name: Optional[str] = None, 
                 encryption: Union[NoEncryption, SymmetricEncryption, AsymmetricEncryption] = NoEncryption(),
                 web_service_url: Optional[str] = None,
                 authorization_password: Optional[str] = None,
                 tables_directory: Optional[str] = TABLES_DIR):
        """
        :param table_name: The table name of the requested table, if it does not exist a new one will be created, if None a random table will be created
        :param encryption: Whether and how the table should be decrypted
        :param web_service_url: If given, tables are stored on a web service
        :param authorization_password: Gives the web service an authorization password if needed
        :param tables_directory: Specifies where tables should be stored
        """

        super().__init__()

        encryption_class_name = encryption.__class__.__name__

        self.encryption = encryption
        self.encryption_class_name = encryption_class_name
        self.web_service_url = web_service_url
        self.authorization_password = authorization_password
        self.tables_directory = tables_directory

        if not self.web_service_url:
            tables = self._request_web_service("/tables")
        else:
            tables = DB.tables(self.tables_directory)

        if not table_name in [table["name"] for table in tables]:
            if table_name == None:
                table_name = random.choice(RANDOM_VERBS) + "_" + random.choice(RANDOM_NOUNS)

                while table_name in [table["name"] for table in tables]:
                    table_name = random.choice(RANDOM_VERBS) + "_" + random.choice(RANDOM_NOUNS)

            self.table_name = table_name
            self.table_path = os.path.join(self.tables_directory, table_name + ".table")

            if not self.web_service_url is None:
                self._request_web_service("/set?table=" + self.table_name + "&content=" + quote(encryption_class_name + "--&&--"))
            else:
                with open(self.table_path, "w") as writeable_file:
                    writeable_file.write(encryption_class_name + "--&&--")
        
        else:
            self.table_name = table_name
            self.table_path = os.path.join(self.tables_directory, table_name + ".table")
            
            if not self.web_service_url is None:
                file_content = self._request_web_service("/get?table=" + self.table_name)
            else:
                with open(self.table_path, "r") as readable_file:
                    file_content = readable_file.read()
            
            if not encryption_class_name == file_content.split("--&&--")[0]:
                raise Exception("[Database Encryption Exception] The specified encryption class cannot decrypt the given table / the table was not created with it.")
    
    @staticmethod
    def tables(tables_directory: str = TABLES_DIR):
        """
        Returns all tables
        :param tables_directory: Specifies where tables are be stored
        """
        files = []
        for file in os.listdir(tables_directory):
            if file.endswith(".table"):
                with open(os.path.join(tables_directory, file), "r") as readable_file:
                    file_content = readable_file.read()
                
                files.append({
                    "name": file.replace(".table", ""),
                    "encryption": file_content.split("--&&--")[0]
                })
        
        return files
    
    @staticmethod
    def _load(table_path):
        """
        Function to load the content of a table
        :param table_path: The Path to the Table
        """
        
        with open(table_path, "r") as readable_file:
            table_content = readable_file.read().split("--&&--")[1]
        
        if table_content == "":
            return {}
        
        table_content = json.loads(table_content)

        return table_content
    
    def _request_web_service(self, endpoint: str):
        """
        Function for authorized request of the web service with a specific endpoint
        :param endpoint: The Requested Endpoint
        """

        request_url = self.web_service_url + endpoint
        if not self.authorization_password is None:
            hashed_password = Hashing().hash(self.authorization_password)

            special_character = "?"
            if "?" in request_url:
                special_character = "&"

            request_url += special_character + "authorization=" + quote(hashed_password)

        response = requests.get(request_url).json()

        if not response["status_code"] == 200:
            raise Exception("[WebService Request Exception] " + response["error"])
        
        return response["content"]

    def _decrypt_value(self, value: str) -> Union[dict, list, set, int, float, bool, bytes]:
        """
        Decrypts a Value
        """

        decrypted_value = self.encryption.decrypt(value)

        _type = decrypted_value.split("//&&//")[1]
        decrypted_value = decrypted_value.split("//&&//")[0]
        type_mappings = {"dict": json.loads, "list": json.loads, "set": json.loads, "int": int, "float": float, "bool": bool, "bytes": str.encode, }

        return type_mappings.get(_type, str)(decrypted_value)

    def _encrypt_value(self, value: Union[dict, list, set, int, float, bool, bytes]) -> str:
        """
        Encrypts a Value
        """

        type_mappings = {"dict": json.dumps, "list": json.dumps, "set": json.dumps, "bytes": bytes.decode, }
        _type = type(value).__name__

        value = type_mappings.get(_type, str)(value) + "//&&//" + _type

        encrypted_value = self.encryption.encrypt(value)
        return encrypted_value
    
    def _save(self, dictionary: dict) -> None:
        """
        Function to save the current content of the table
        :param dictionary: The current content of the table as a dictionary
        """

        dictionary = json.dumps(dictionary)

        if not self.web_service_url is None:
            self._request_web_service("/set?table=" + self.table_name + "&content=" + quote(dictionary))
            return
        
        with open(self.table_path, "r") as readable_file:
            file_content = readable_file.read()
        
        file_content = file_content.split("--&&--")[0] + "--&&--" + dictionary

        with open(self.table_path, "w") as writeable_file:
            writeable_file.write(file_content)
    
    def __getitem__(self, key):
        if not self.web_service_url is None:
            table_content = self._request_web_service("/get?table=" + self.table_name).split("--&&--")[1]
            if table_content == "":
                return {}
            else:
                table_content = json.loads(table_content)
        else:
            table_content = DB._load(self.table_path)

        key_value = None
        for table_key, table_value in table_content.items():
            if self.encryption.use_hashing:
                if Hashing().compare(key, table_key):
                    key_value = table_value
                    break
            else:
                if key == table_key:
                    key_value = table_value
                    break
        
        if key_value is None:
            return None
        
        return self._decrypt_value(key_value)
    
    def __setitem__(self, key, value):
        if not self.web_service_url is None:
            table_content = self._request_web_service("/get?table=" + self.table_name).split("--&&--")[1]
            if table_content == "":
                table_content = {}
            else:
                table_content = json.loads(table_content)
        else:
            table_content = DB._load(self.table_path)

        key_hash = None
        for table_key, _ in table_content.items():
            if self.encryption.use_hashing:
                if Hashing().compare(key, table_key):
                    key_hash = table_key
                    break
            else:
                if key == table_key:
                    key_hash = table_key
                    break
        
        if key_hash is None:
            if self.encryption.use_hashing:
                key = Hashing().hash(key)
        else:
            key = key_hash
        
        value = self._encrypt_value(value)

        table_content[key] = value

        if not self.web_service_url is None:
            self._request_web_service("/set?table=" + self.table_name + "&content=" + quote(self.encryption_class_name + "--&&--" + json.dumps(table_content)))
        else:
            self._save(table_content)

class WebService:
    def __init__(self, authorization_password: Optional[str] = None,
                 tabels_directory: Optional[str] = TABLES_DIR):
        """
        :param authorization_password: Gives access only to requests with a hash of the password given here
        :param tables_directory: Specifies where tables should be stored
        """

        self.authorization_password = authorization_password
        self.tables_directory = tabels_directory
        app = Flask("RapidDB")

        @app.route("/")
        def index():
            if not self._is_authorized:
                return {"status_code": 401, "error": "Unauthorized - The client must authorize itself to receive the requested resource."}, 401
            return "RapidDB WebService instance"
        
        @app.route("/tables")
        def tables():
            if not self._is_authorized:
                return {"status_code": 401, "error": "Unauthorized - The client must authorize itself to receive the requested resource."}, 401
            return {"status_code": 200, "error": None, "content": DB.tables(self.tables_directory)}
        
        @app.route("/get")
        def get():
            if not self._is_authorized:
                return {"status_code": 401, "error": "Unauthorized - The client must authorize itself to receive the requested resource."}, 401
            table_name = request.args.get("table")
            if table_name is None:
                return {"status_code": 400, "error": "Bad Request - The 'table' argument was not passed by the client."}, 400
            table_path = os.path.join(self.tables_directory, table_name + ".tabel")
            if not os.path.isfile(table_path):
                return {"status_code": 400, "error": "Bad Request - The client has given a table with the argument 'table' which does not exist."}, 400
            with open(table_path, "r") as readable_file:
                table_content = readable_file.read()
            return {"status_code": 200, "error": None, "content": table_content}
        
        @app.route("/set")
        def set():
            if not self._is_authorized:
                return {"status_code": 401, "error": "Unauthorized - The client must authorize itself to receive the requested resource."}, 401
            table_name = request.args.get("table")
            if table_name is None:
                return {"status_code": 400, "error": "Bad Request - The 'table' argument was not passed by the client."}, 400
            table_content = request.args.get("content")
            if table_content is None:
                return {"status_code": 400, "error": "Bad Request - The 'table_content' argument was not passed by the client."}, 400
            table_path = os.path.join(self.tables_directory, table_name + ".tabel")
            with open(table_path, "w") as writeable_file:
                writeable_file.write(table_content)
            return {"status_code": 200, "error": None, "content": None}
        
        self.app = app
    
    def _is_authorized(self):
        return True
    
    def run(self, host: str, port: int, as_thread: bool = False):
        """
        Runs the database online
        :param host: See Flask().run
        :param port: See Flask().run
        :param as_thread: If True the Flask app is started in the background
        """

        def start_app():
            self.app.run(host, port)

        if as_thread:
            thread = Thread(target=start_app)
            thread.start()
            return
        
        start_app()
