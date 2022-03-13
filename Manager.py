import config
import datetime
import database as db
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

    def addProfile(self, profile_name: str, username: str, password: str) -> bool:
        '''
        Adding new profile

        Args:
            profile_name: Name of the new profile
            username: Username of the new profile
            password: Password of the new profile
        
        Returns:
            result (bool): True - success, False - fail
        '''
        new_username = self.encryptData(username, self.hashedMasterPswd)
        new_password = self.encryptData(password, self.hashedMasterPswd)
        self.profiles[profile_name] = (new_username, new_password)
        if db.newProfile(profile_name, new_username.decode('utf-8'), new_password.decode('utf-8'), database=self.db):
            return True
        del self.profiles[profile_name]
        return False

    def updateProfile(self, profile_name: str, new_name: str, new_usr: str, new_pswd: str) -> bool:
        '''
        Updating profile's credentials

        Args:
            profile_name (str): Name of the profile to be changed
            new_name (str): New name of the profile
            new_usr (str): New username of the profile
            new_pswd (str): New password of the profile

        Returns:
            result (bool): True - success, False - fail
        '''
        username = self.encryptData(new_usr, self.hashedMasterPswd)
        password = self.encryptData(new_pswd, self.hashedMasterPswd)
        self.profiles[new_name] = (username, password)
        if new_name != profile_name:
            del self.profiles[profile_name]
        if db.updateProfile(profile_name, new_name, username.decode('utf-8'), password.decode('utf-8'), self.db):
            return True
        if new_name != profile_name:
            del self.profiles[new_name]
        return False

    def getProfile(self, service_name: str) -> Tuple[str]:
        '''
        Get profile username and password

        Args:
            service_name (Dict): Name of the service
        
        Retuns:
            creds (Tuple[str]): (username, password) of service
        
        '''
        usr_hash, psswd_hash = self.profiles[service_name]
        return (self.decrypteData(usr_hash, self.hashedMasterPswd), self.decrypteData(psswd_hash, self.hashedMasterPswd))

    def deleteProfile(self, service_name: str) -> bool:
        '''
        Deleting User's profile
        
        Args:
            service_name: Name of the service to delete

        Returns: 
            result (bool): True - success, False - fail
        '''
        if db.deleteProfile(service_name, self.db):
            del self.profiles[service_name]
            return True
        return False

    def checkMasterPassword(self, password: str, salt: bytes, verify: bytes) -> bool:
        '''
        Checks if hashed with particular salt password is actual password

        Args:
            password (str): Raw input of the password
            salt (bytes): Salt to hash password with
            verify (bytes): Hashed actual master password

        Returns:
            result (bool): True - password is verified, False - password is NOT verified
        '''
        hash = self.hashPassword(password, salt)
        return verify == hash

    def hashPassword(self, master_pswd: str, salt: bytes) -> bytes:
        '''
        Returns hashed master password

        Args:
            master_pswd (str): Raw master password
            salt (bytes): Salt for the password hashing

        Returns:
            hashed_pswd (bytes): Hashed master password
        '''
        pswd_encoded = master_pswd.encode()
        kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), salt=salt, iterations=390000, length=32)
        hashed_pswd = base64.urlsafe_b64encode(kdf.derive(pswd_encoded))
        return hashed_pswd