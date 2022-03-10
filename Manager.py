import config
import datetime
from typing import List, Dict, Tuple
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Manager:

    def __init__(self, database: Tuple = None, profiles: List[Dict] = None):
        '''
        Args:
            profiles (List[Dict]): List of dictionaries with profiles from database
                {service_name: (username_hash, password_hash)}
        '''
        self.hashedMasterPswd = None
        self.last_usage = None
        self.profiles = profiles
        self.db = database

    def isPswdValid(self) -> bool:
        '''
        Returns if recently entered master password is still valid
        According to config.MASTERKEY_VALIDATION

        Returns:
            result (bool): False - invalid, True - valid
        '''
        if self.last_usage == None or type(self.last_usage) != datetime.datetime:
            self.hashedMasterPswd = None
            return False
        delta = datetime.datetime.now() - self.last_usage
        if delta.total_seconds() // 3600 <= config.MASTERKEY_VALIDATION:
            return True
        self.hashedMasterPswd = None
        return False

    def encryptData(self, data: str, pswd_hash: bytes) -> bytes:
        '''
        Returns encrypted by password_hash data

        Args:
            data (str): Data to encrypt
            pswd_hash (bytes): Hashed master password

        Returns:
            data_encrypted (bytes): Encrypted data
        '''
        fernet = Fernet(pswd_hash)
        data_encrypted = fernet.encrypt(data.encode())
        return data_encrypted
    
    def decrypteData(self, data: bytes, pswd_hash: bytes):
        '''
        Returns decrypted message from data using pswd_hash

        Args:
            data (bytes): Data to decrypt
            pswd_hash (bytes): Hashed master password

        Returns:
            data_decrypted (str): Decrypted message from data
            False : Invalid pswd_hash
        '''
        try:
            fernet = Fernet(pswd_hash)
            data_decrypted = fernet.decrypt(data)
            return data_decrypted.decode('utf-8')
        except InvalidToken:
            print('Invalid hashed password')
            return False
        
    def hashMasterPassword(self, master_pswd: str) -> bytes:
        '''
        Returns hashed master password

        Args:
            master_pswd (str): Raw master password

        Returns:
            hashed_pswd (bytes): Hashed master password
        '''
        pswd_encoded = master_pswd.encode()
        kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), salt= ''.encode(), iterations=390000, length=32)
        hashed_pswd = base64.urlsafe_b64encode(kdf.derive(pswd_encoded))
        return hashed_pswd