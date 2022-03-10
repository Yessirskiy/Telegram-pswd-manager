import config
import database
from typing import List, Dict
from cryptography.fernet import Fernet
import hashlib

class Manager:

    def __init__(self, profiles: List[Dict] = None):
        '''
        Args:
            profiles (List[Dict]): List of dictionaries with profiles from database
                {service_name: (username_hash, password_hash)}
        '''
        self.hashedMasterPswd = None
        self.last_usage = None
        self.profiles = profiles

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
    
    def decryptedData(self, data: bytes, pswd_hash: bytes) -> str:
        '''
        Returns decrypted message from data using pswd_hash

        Args:
            data (bytes): Data to decrypt
            pswd_hash (bytes): Hashed master password

        Returns:
            data_decrypted (str): Decrypted message from data
        '''
        fernet = Fernet(pswd_hash)
        data_decrypted = str(fernet.decrypt(data))
        return data_decrypted

    def hashMasterPassword(self, master_pswd: str) -> bytes:
        '''
        Returns hashed master password

        Args:
            master_pswd (str): Raw master password

        Returns:
            hashed_pswd (bytes): Hashed master password
        '''
        pswd_encoded = master_pswd.encode()
        hashed_pswd = hashlib.pbkdf2_hmac(hash_name='sha256', salt=''.encode(), password=pswd_encoded, iterations=100000, dklen=128)
        return hashed_pswd